//! Observation-only physical joins for the installed atomic lifecycle.
//!
//! This module never opens the lifecycle-command journal. Startup performs one
//! descriptor-safe enumeration of provider-private final/progress manifests,
//! then joins those immutable identities to fresh process, cgroup, VMM,
//! network, frontend, blockd, and Volume-authority facts. The registry owns the
//! sole startup journal enumeration and overlays it onto this exact snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse, DurabilityStatus};
use cats_api::runtime_inventory::{
    ObservedArtifactClassification, ObservedCatRuntimeTelemetry, ObservedRuntimeCondition,
    ObservedRuntimeConditionKind, ObservedRuntimePhysicalState, ObservedVolumeAttachment,
    ObservedVolumeWatermark, ObservedVolumeWatermarkSummary,
};
use cats_api::runtime_lifecycle::{
    LifecycleCommandEnvelope, LifecycleCommandResponse, NodeResult, VolumeTerminalReceipt,
};
use cats_api::runtime_reconciliation::{
    Generation, Id, ProcessState, RandomId128, Sha256Digest, UnixMillis, VolumeAdminState,
};
use cats_storage::authority::{
    validate_volume_owner_binding, validate_volume_record, NodeVolumeInventoryRecord,
};

use crate::cat_execution_scope::{
    cat_execution_slice_id, cat_service_control_group, is_cat_execution_slice_name,
};
use crate::ch::{inspect_host_network_snapshot, HostNetworkSnapshot, ReservedHostNetworkState};
use crate::physical_read::PhysicalReadContext;
use crate::runtime_inventory::{inspect_installed_vmm_api, InstalledVmmApiInspection};

use super::super::journal::StartupPhysicalInventory;
use super::start::{
    enumerate_installed_runtime_manifests, enumerate_installed_start_physical_manifests,
    InstalledRuntimeBlockFrontend, InstalledRuntimeManifest, InstalledRuntimeProcessIdentity,
    InstalledRuntimeProgressManifest, InstalledRuntimeVmmManifest, InstalledRuntimeVolumeManifest,
    InstalledStartPhysicalInventoryEntry, TerminalRetainedRuntimeManifest,
    TerminalRetainedRuntimeMode,
};
use super::suspend_warm::{
    enumerate_installed_warm_snapshot_artifacts, InstalledPreparedWarmSnapshotArtifact,
    InstalledWarmIntentContentObservation, InstalledWarmSnapshotArtifact,
    InstalledWarmSnapshotIntentArtifact, InstalledWarmSnapshotInventoryEntry,
};
use super::{
    artifact_id, digest_parts, quarantined_artifact, read_unified_process_cgroup,
    scan_exact_cgroup_tree, scan_kernel_nbd_pool, InstalledPhysicalInspectionConfig, KernelNbdSlot,
};

const PHYSICAL_JOIN_DOMAIN: &[u8] = b"cats.atomic-lifecycle.installed-physical-join.v1";
const RESTART_SOURCE_ABSENCE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.restart-source-absence.v1";
const BLOCKD_CONTROL_MAX_LINE_BYTES: usize = 1_048_576;
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(20);
const GLOBAL_PHYSICAL_ENTRY_LIMIT: usize = 131_072;
const MANAGED_SOCKET_TREE_DEPTH_LIMIT: usize = 32;
const DELETED_EXECUTABLE_SUFFIX: &[u8] = b" (deleted)";
const LINEAGE_NAMESPACE: &str = "data";
const LINEAGE_DEPTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstalledPhysicalVmmState {
    Executing,
    Paused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstalledRuntimePhysicalJoin {
    pub(crate) manifest: InstalledRuntimeManifest,
    pub(crate) vmm_state: InstalledPhysicalVmmState,
    pub(crate) volume_receipts: Vec<VolumeTerminalReceipt>,
    pub(crate) physical_identity_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstalledRuntimePhysicalAbsence {
    pub(crate) manifest: InstalledRuntimeManifest,
    pub(crate) physical_identity_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstalledRuntimePhysicalOutcome {
    Exact(InstalledRuntimePhysicalJoin),
    Absent(InstalledRuntimePhysicalAbsence),
    Unavailable,
    Conflict,
}

struct ReadDeadline {
    deadline: Instant,
}

impl PhysicalReadContext for ReadDeadline {
    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn check_active(&self) -> Result<()> {
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "installed physical inventory deadline elapsed"
        );
        Ok(())
    }
}

struct PhysicalInputs {
    authority: BTreeMap<Id, NodeVolumeInventoryRecord>,
    networks: HostNetworkSnapshot,
}

/// Provider-private identities retained from the exact same descriptor scan
/// as `physical`. The runner never interprets these manifests; it passes this
/// value back to the installed executor after the sole journal enumeration so
/// Start ambiguity can be bound without a second filesystem scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InstalledStartupPhysicalEvidence {
    pub(super) scan_id: RandomId128,
    pub(super) start_physical: Vec<InstalledStartPhysicalInventoryEntry>,
}

pub(super) fn scan_startup_inventory(
    config: &InstalledPhysicalInspectionConfig,
) -> Result<(StartupPhysicalInventory, InstalledStartupPhysicalEvidence)> {
    let deadline = Instant::now()
        .checked_add(config.inventory_timeout)
        .context("startup inventory deadline overflow")?;
    let read = ReadDeadline { deadline };
    let state_scan_root = config
        .state_directory
        .try_clone_directory()
        .context("retain identity-selected StateDirectory for complete physical inventory")?;
    let finals = enumerate_installed_runtime_manifests(&config.state_directory)
        .context("enumerate installed RuntimeReady manifests")?;
    let start_physical = enumerate_installed_start_physical_manifests(&config.state_directory)
        .context("enumerate installed atomic Start physical manifests")?;
    let startup_start_physical = start_physical.clone();
    let mut progress = Vec::new();
    let mut terminal_retained = Vec::new();
    for entry in start_physical {
        match entry {
            InstalledStartPhysicalInventoryEntry::Executing(manifest) => progress.push(*manifest),
            InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest) => {
                terminal_retained.push(*manifest);
            }
        }
    }
    let warm = enumerate_installed_warm_snapshot_artifacts(config, deadline)
        .context("enumerate installed Warm snapshot artifacts")?;
    let expected_lineages = expected_canonical_lineages(
        &config.state_directory,
        &finals,
        &progress,
        &terminal_retained,
        &warm,
    )?;
    let mut lineage_unattributed = expected_lineages.source_quarantines.clone();
    classify_canonical_lineage_namespace(
        &state_scan_root,
        &expected_lineages,
        deadline,
        GLOBAL_PHYSICAL_ENTRY_LIMIT,
        &mut lineage_unattributed,
    )
    .context("enumerate canonical local-lineage namespace")?;
    read.check_active()?;

    let candidates = finals
        .iter()
        .flat_map(|manifest| {
            manifest
                .volumes
                .iter()
                .map(|volume| volume.volume_id.clone())
        })
        .chain(progress.iter().flat_map(|manifest| {
            manifest
                .volumes
                .iter()
                .map(|volume| volume.volume_id.clone())
        }))
        .chain(terminal_retained.iter().flat_map(|manifest| {
            manifest
                .retained_volume_receipts
                .iter()
                .map(|volume| volume.volume_id.clone())
        }))
        .chain(warm.iter().flat_map(|entry| {
            match entry {
                InstalledWarmSnapshotInventoryEntry::Terminal(artifact) => artifact
                    .retained_volume_receipts
                    .iter()
                    .map(|receipt| receipt.volume_id.clone())
                    .collect::<Vec<_>>(),
                InstalledWarmSnapshotInventoryEntry::RetainedPrepared(artifact) => artifact
                    .retained_volume_receipts
                    .iter()
                    .map(|receipt| receipt.volume_id.clone())
                    .collect::<Vec<_>>(),
                InstalledWarmSnapshotInventoryEntry::RetainedIntent(artifact) => artifact
                    .retained_volume_receipts
                    .iter()
                    .map(|receipt| receipt.volume_id.clone())
                    .collect::<Vec<_>>(),
                InstalledWarmSnapshotInventoryEntry::Quarantined { .. } => Vec::new(),
            }
        }))
        .collect::<BTreeSet<_>>();
    let snapshot = config
        .volume_inventory_authority
        .load_node_volume_inventory(&config.node_id, &candidates)
        .context("load complete installed Volume authority snapshot")?;
    anyhow::ensure!(
        snapshot.node_id == config.node_id,
        "installed Volume inventory belongs to another Node"
    );
    let mut authority = BTreeMap::new();
    for record in snapshot.records {
        validate_volume_record(&record.volume)
            .context("validate installed Volume authority row")?;
        if let Some(binding) = &record.binding {
            validate_volume_owner_binding(binding, &record.volume)
                .context("validate installed Volume owner binding")?;
        }
        anyhow::ensure!(
            authority
                .insert(record.volume.volume_id.clone(), record)
                .is_none(),
            "installed Volume inventory contains duplicate rows"
        );
    }
    anyhow::ensure!(
        candidates
            .iter()
            .all(|candidate| authority.contains_key(candidate)),
        "installed Volume inventory omitted a manifest candidate"
    );
    let networks = inspect_host_network_snapshot(&config.ip_binary, &read)
        .context("inspect complete installed Host network snapshot")?;
    let inputs = PhysicalInputs {
        authority,
        networks,
    };

    let mut final_by_cat = BTreeMap::new();
    for manifest in finals {
        anyhow::ensure!(
            manifest.node_id == config.node_id
                && manifest.placement_identity.node_id == config.node_id,
            "installed RuntimeReady manifest belongs to another Node"
        );
        anyhow::ensure!(
            final_by_cat
                .insert(manifest.cat_id.clone(), manifest)
                .is_none(),
            "installed RuntimeReady manifests repeat a Cat"
        );
    }
    let mut progress_by_cat: BTreeMap<Id, Vec<InstalledRuntimeProgressManifest>> = BTreeMap::new();
    for manifest in progress {
        anyhow::ensure!(
            manifest.node_id == config.node_id
                && manifest.placement_identity.node_id == config.node_id,
            "installed Start progress belongs to another Node"
        );
        progress_by_cat
            .entry(manifest.cat_id.clone())
            .or_default()
            .push(manifest);
    }
    let mut terminal_retained_by_cat: BTreeMap<Id, Vec<TerminalRetainedRuntimeManifest>> =
        BTreeMap::new();
    for manifest in terminal_retained {
        anyhow::ensure!(
            manifest.node_id == config.node_id
                && manifest.placement_identity.node_id == config.node_id,
            "terminal retained Start manifest belongs to another Node"
        );
        terminal_retained_by_cat
            .entry(manifest.cat_id.clone())
            .or_default()
            .push(manifest);
    }

    let mut warm_terminal_by_cat: BTreeMap<Id, Vec<InstalledWarmSnapshotArtifact>> =
        BTreeMap::new();
    let mut warm_prepared_by_cat: BTreeMap<Id, Vec<InstalledPreparedWarmSnapshotArtifact>> =
        BTreeMap::new();
    let mut warm_intent_by_cat: BTreeMap<Id, Vec<InstalledWarmSnapshotIntentArtifact>> =
        BTreeMap::new();
    let mut warm_unattributed = Vec::new();
    for entry in warm {
        match entry {
            InstalledWarmSnapshotInventoryEntry::Terminal(artifact)
                if artifact.node_id == config.node_id
                    && artifact.placement_identity.node_id == config.node_id =>
            {
                warm_terminal_by_cat
                    .entry(artifact.cat_id.clone())
                    .or_default()
                    .push(*artifact);
            }
            InstalledWarmSnapshotInventoryEntry::RetainedPrepared(artifact)
                if artifact.node_id == config.node_id
                    && artifact.placement_identity.node_id == config.node_id =>
            {
                warm_prepared_by_cat
                    .entry(artifact.cat_id.clone())
                    .or_default()
                    .push(*artifact);
            }
            InstalledWarmSnapshotInventoryEntry::RetainedIntent(artifact)
                if artifact.node_id == config.node_id
                    && artifact.placement_identity.node_id == config.node_id =>
            {
                warm_intent_by_cat
                    .entry(artifact.cat_id.clone())
                    .or_default()
                    .push(*artifact);
            }
            InstalledWarmSnapshotInventoryEntry::Terminal(artifact) => {
                warm_unattributed.push(quarantined_artifact(
                    "foreign-warm-terminal",
                    artifact.terminal_manifest_digest.as_bytes(),
                )?);
            }
            InstalledWarmSnapshotInventoryEntry::RetainedPrepared(artifact) => {
                warm_unattributed.push(quarantined_artifact(
                    "foreign-warm-prepared",
                    artifact.prepared_manifest_digest.as_bytes(),
                )?);
            }
            InstalledWarmSnapshotInventoryEntry::RetainedIntent(artifact) => {
                warm_unattributed.push(quarantined_artifact(
                    "foreign-warm-intent",
                    artifact.intent_manifest_digest.as_bytes(),
                )?);
            }
            InstalledWarmSnapshotInventoryEntry::Quarantined {
                artifact_id,
                evidence_digest,
            } => warm_unattributed.push(
                ObservedArtifactClassification::QuarantinedForeignOrAmbiguous {
                    artifact_id,
                    evidence_digest,
                },
            ),
        }
    }
    for artifacts in warm_terminal_by_cat.values_mut() {
        artifacts.sort_by(|left, right| {
            left.source_operation_id
                .cmp(&right.source_operation_id)
                .then_with(|| {
                    left.terminal_manifest_digest
                        .as_str()
                        .cmp(right.terminal_manifest_digest.as_str())
                })
        });
    }
    for artifacts in warm_prepared_by_cat.values_mut() {
        artifacts.sort_by(|left, right| {
            left.source_operation_id
                .cmp(&right.source_operation_id)
                .then_with(|| {
                    left.prepared_manifest_digest
                        .as_str()
                        .cmp(right.prepared_manifest_digest.as_str())
                })
        });
    }
    for artifacts in warm_intent_by_cat.values_mut() {
        artifacts.sort_by(|left, right| {
            left.source_operation_id
                .cmp(&right.source_operation_id)
                .then_with(|| {
                    left.intent_manifest_digest
                        .as_str()
                        .cmp(right.intent_manifest_digest.as_str())
                })
        });
    }

    let mut all_cat_ids = final_by_cat.keys().cloned().collect::<BTreeSet<_>>();
    all_cat_ids.extend(progress_by_cat.keys().cloned());
    all_cat_ids.extend(terminal_retained_by_cat.keys().cloned());
    all_cat_ids.extend(warm_terminal_by_cat.keys().cloned());
    all_cat_ids.extend(warm_prepared_by_cat.keys().cloned());
    all_cat_ids.extend(warm_intent_by_cat.keys().cloned());
    let mut cats = Vec::with_capacity(all_cat_ids.len());
    for cat_id in all_cat_ids {
        read.check_active()?;
        let final_manifest = final_by_cat.get(&cat_id);
        let progress_manifests = progress_by_cat
            .get(&cat_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let retained_manifests = terminal_retained_by_cat
            .get(&cat_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut projection = if progress_manifests.len() > 1
            || final_manifest.is_some_and(|final_manifest| {
                progress_manifests.iter().any(|progress| {
                    progress.source_lifecycle_operation_id
                        != final_manifest.source_lifecycle_operation_id
                        || progress.runtime_incarnation != final_manifest.runtime_incarnation
                        || progress.runtime_config_digest != final_manifest.runtime_config_digest
                })
            }) {
            conflicting_manifest_projection(final_manifest, progress_manifests)?
        } else if let Some(manifest) = final_manifest {
            project_final_manifest(config, &inputs, manifest, &read)?
        } else if let Some(manifest) = progress_manifests.first() {
            project_progress_manifest(config, &inputs, manifest, &read)?
        } else if !retained_manifests.is_empty() {
            project_terminal_retained_manifests(config, &inputs, retained_manifests, &read)?
        } else {
            warm_only_ambiguous_projection(
                &cat_id,
                warm_terminal_by_cat.get(&cat_id).map(Vec::as_slice),
                warm_prepared_by_cat.get(&cat_id).map(Vec::as_slice),
                warm_intent_by_cat.get(&cat_id).map(Vec::as_slice),
            )?
        };
        overlay_warm_artifacts(
            &inputs,
            final_manifest,
            warm_terminal_by_cat
                .get(&cat_id)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            warm_prepared_by_cat
                .get(&cat_id)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            warm_intent_by_cat
                .get(&cat_id)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            &mut projection,
        )?;
        overlay_terminal_retained_manifests(retained_manifests, &mut projection)?;
        cats.push(projection);
    }

    let referenced_volumes = final_by_cat
        .values()
        .flat_map(|manifest| manifest.volumes.iter().map(|volume| &volume.volume_id))
        .chain(
            progress_by_cat
                .values()
                .flatten()
                .flat_map(|manifest| manifest.volumes.iter().map(|volume| &volume.volume_id)),
        )
        .chain(
            terminal_retained_by_cat
                .values()
                .flatten()
                .flat_map(|manifest| {
                    manifest
                        .retained_volume_receipts
                        .iter()
                        .map(|volume| &volume.volume_id)
                }),
        )
        .chain(warm_intent_by_cat.values().flatten().flat_map(|artifact| {
            artifact
                .retained_volume_receipts
                .iter()
                .map(|receipt| &receipt.volume_id)
        }))
        .chain(
            warm_terminal_by_cat
                .values()
                .flatten()
                .flat_map(|artifact| {
                    artifact
                        .retained_volume_receipts
                        .iter()
                        .map(|receipt| &receipt.volume_id)
                }),
        )
        .chain(
            warm_prepared_by_cat
                .values()
                .flatten()
                .flat_map(|artifact| {
                    artifact
                        .retained_volume_receipts
                        .iter()
                        .map(|receipt| &receipt.volume_id)
                }),
        )
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut unattributed_artifacts = Vec::new();
    unattributed_artifacts.extend(warm_unattributed);
    unattributed_artifacts.extend(lineage_unattributed);
    for (volume_id, record) in &inputs.authority {
        if record.binding.is_some() && !referenced_volumes.contains(volume_id) {
            unattributed_artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
                artifact_id: artifact_id(
                    "unattributed-node-volume",
                    volume_id.as_str().as_bytes(),
                )?,
                evidence_digest: authority_evidence_digest(record),
            });
        }
    }
    let reserved_networks = final_by_cat
        .values()
        .map(|manifest| manifest.network.identity.as_ref())
        .chain(
            progress_by_cat
                .values()
                .flatten()
                .filter_map(|manifest| manifest.network.as_ref())
                .map(|network| network.identity.as_ref()),
        )
        .collect::<Vec<_>>();
    for residue in inputs
        .networks
        .unreserved_managed_networks(reserved_networks.iter().copied())
        .context("classify unreserved installed Host networks")?
    {
        let evidence = format!(
            "{}:{}:{}",
            residue.network_id, residue.tap_name, residue.ownership_token
        );
        unattributed_artifacts.push(quarantined_artifact(
            "unreserved-managed-network",
            evidence.as_bytes(),
        )?);
    }
    quarantine_retired_checkpoint_namespace(
        &config.state_directory.path().join("checkpoints"),
        deadline,
        &mut unattributed_artifacts,
    )?;
    classify_global_physical_residue(
        config,
        &final_by_cat,
        &progress_by_cat,
        deadline,
        &mut unattributed_artifacts,
    )?;
    revalidate_state_scan_root(&config.state_directory, &state_scan_root)
        .context("revalidate complete physical inventory StateDirectory authority")?;

    cats.sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
    unattributed_artifacts.sort_by(|left, right| left.artifact_id().cmp(right.artifact_id()));
    unattributed_artifacts.dedup_by(|left, right| left == right);
    ensure_no_installed_gc_candidates(&cats, &unattributed_artifacts)?;
    let scan_id = RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
        .context("generate installed physical scan identity")?;
    Ok((
        StartupPhysicalInventory::Complete {
            scan_id: scan_id.clone(),
            collected_at_unix_ms: current_unix_millis()?,
            cats,
            unattributed_artifacts,
        },
        InstalledStartupPhysicalEvidence {
            scan_id,
            start_physical: startup_start_physical,
        },
    ))
}

/// The installed release currently has no command-created inert artifact
/// whose deletion is both useful and independently closed by typed ownership
/// plus postcondition evidence. Retained Start/Warm/Volume evidence and every
/// quarantine therefore remain outside generic GC. Keep this assertion at
/// the final scan boundary so a future producer cannot silently create a
/// destructive work queue without adding the matching restart-safe executor.
pub(super) fn ensure_no_installed_gc_candidates(
    cats: &[ObservedCatRuntimeTelemetry],
    unattributed: &[ObservedArtifactClassification],
) -> Result<()> {
    let cat_candidate = cats.iter().find_map(|cat| {
        cat.observed_artifact_classifications
            .iter()
            .find(|artifact| {
                matches!(
                    artifact,
                    ObservedArtifactClassification::CatOwnedGcCandidate { .. }
                )
            })
            .map(|artifact| (&cat.cat_id, artifact.artifact_id()))
    });
    anyhow::ensure!(
        cat_candidate.is_none(),
        "installed scan produced a Cat-owned GC candidate without a composed executor"
    );
    anyhow::ensure!(
        !unattributed.iter().any(|artifact| matches!(
            artifact,
            ObservedArtifactClassification::CatOwnedGcCandidate { .. }
        )),
        "unattributed artifact cannot be a Cat-owned GC candidate"
    );
    Ok(())
}

/// Canonical per-Cat proof that the exact post-Stop scan exposes no armed
/// restart/adoption source for the journal generation which performed Stop.
///
/// A sealed observation/retry carrier may remain `RetainedAuthorityOrData`;
/// it is included in the digest but grants no execution. Executing, paused,
/// Warm-adoptable, ambiguous, quarantined or GC-candidate projections cannot
/// manufacture absence. Other Cats are deliberately outside this receipt so
/// one quarantined sibling cannot suppress an exact terminal result.
pub(super) fn installed_restart_source_absence_receipt_digest(
    command: &LifecycleCommandEnvelope,
    journal_content_digest: &Sha256Digest,
    inventory: &StartupPhysicalInventory,
) -> Result<Sha256Digest> {
    let StartupPhysicalInventory::Complete { scan_id, cats, .. } = inventory else {
        anyhow::bail!("restart-source absence requires one complete physical scan")
    };
    anyhow::ensure!(
        command.node_id == command.placement_identity.node_id
            && cats.windows(2).all(|pair| pair[0].cat_id < pair[1].cat_id),
        "restart-source absence command or Cat scan is not canonical"
    );
    let matching = cats
        .iter()
        .filter(|cat| cat.cat_id == command.cat_id)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        matching.len() <= 1,
        "restart-source absence scan repeats the target Cat"
    );

    let (physical_state, physical_manifest_digest, classifications) = if let Some(cat) =
        matching.first().copied()
    {
        anyhow::ensure!(
            cat.observed_placement == command.placement_identity
                && cat.observed_command_journal.is_none()
                && cat.observed_runtime_incarnation.is_none()
                && matches!(
                    cat.observed_physical_state,
                    ObservedRuntimePhysicalState::Absent
                        | ObservedRuntimePhysicalState::StoppedRetained
                )
                && cat
                    .observed_artifact_classifications
                    .windows(2)
                    .all(|pair| pair[0].artifact_id() < pair[1].artifact_id()),
            "post-Stop target Cat still has an executable, ambiguous, or noncanonical projection"
        );
        for artifact in &cat.observed_artifact_classifications {
            anyhow::ensure!(
                    matches!(
                        artifact,
                        ObservedArtifactClassification::RetainedAuthorityOrData { .. }
                    ),
                    "post-Stop target Cat retains an adoptable, quarantined, or GC-candidate restart source"
                );
        }
        (
            Some(cat.observed_physical_state),
            Some(&cat.observed_artifact_manifest_digest),
            cat.observed_artifact_classifications.as_slice(),
        )
    } else {
        (None, None, &[][..])
    };

    let canonical =
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&serde_json::json!({
            "version": 1,
            "scan_id": scan_id,
            "command_journal": {
                "operation_id": command.operation_id,
                "command_kind": command.command_kind(),
                "request_fingerprint": command.request_fingerprint,
                "journal_content_digest": journal_content_digest,
            },
            "cat_id": command.cat_id,
            "node_id": command.node_id,
            "placement_identity": command.placement_identity,
            "runtime_config_id": command.runtime_config.config_id,
            "runtime_config_digest": command.runtime_config.config_digest,
            "physical_state": physical_state,
            "physical_manifest_digest": physical_manifest_digest,
            "sorted_restart_source_classifications": classifications,
        }));
    Ok(digest_parts(RESTART_SOURCE_ABSENCE_DOMAIN, &[&canonical]))
}

pub(crate) fn inspect_exact_runtime(
    config: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    deadline: Instant,
) -> Result<InstalledRuntimePhysicalOutcome> {
    let manifests = enumerate_installed_runtime_manifests(&config.state_directory)
        .context("enumerate exact installed runtime manifest")?;
    let Some(manifest) = manifests
        .into_iter()
        .find(|manifest| manifest.cat_id == command.cat_id)
    else {
        return Ok(InstalledRuntimePhysicalOutcome::Unavailable);
    };
    if manifest.node_id != command.node_id
        || manifest.placement_identity != command.placement_identity
        || manifest.runtime_config_id != command.runtime_config.config_id
        || manifest.runtime_config_digest != command.runtime_config.config_digest
        || !predecessor_matches_manifest(predecessor, &manifest)
    {
        return Ok(InstalledRuntimePhysicalOutcome::Conflict);
    }
    let candidates = manifest
        .volumes
        .iter()
        .map(|volume| volume.volume_id.clone())
        .collect::<BTreeSet<_>>();
    let snapshot = config
        .volume_inventory_authority
        .load_node_volume_inventory(&config.node_id, &candidates)
        .context("load exact runtime Volume authority snapshot")?;
    if snapshot.node_id != config.node_id {
        return Ok(InstalledRuntimePhysicalOutcome::Conflict);
    }
    let mut authority = BTreeMap::new();
    for record in snapshot.records {
        if validate_volume_record(&record.volume).is_err()
            || record.binding.as_ref().is_some_and(|binding| {
                validate_volume_owner_binding(binding, &record.volume).is_err()
            })
            || authority
                .insert(record.volume.volume_id.clone(), record)
                .is_some()
        {
            return Ok(InstalledRuntimePhysicalOutcome::Conflict);
        }
    }
    if !candidates
        .iter()
        .all(|volume| authority.contains_key(volume))
    {
        return Ok(InstalledRuntimePhysicalOutcome::Conflict);
    }
    let read = ReadDeadline { deadline };
    let networks = inspect_host_network_snapshot(&config.ip_binary, &read)
        .context("inspect complete exact-runtime Host network snapshot")?;
    let inputs = PhysicalInputs {
        authority,
        networks,
    };
    match inspect_final_manifest(config, &inputs, &manifest, &read)? {
        FinalInspection::Exact {
            vmm_state,
            volume_receipts,
            physical_identity_digest,
        } => Ok(InstalledRuntimePhysicalOutcome::Exact(
            InstalledRuntimePhysicalJoin {
                manifest,
                vmm_state,
                volume_receipts,
                physical_identity_digest,
            },
        )),
        FinalInspection::Absent {
            physical_identity_digest,
        } => Ok(InstalledRuntimePhysicalOutcome::Absent(
            InstalledRuntimePhysicalAbsence {
                manifest,
                physical_identity_digest,
            },
        )),
        FinalInspection::Unavailable => Ok(InstalledRuntimePhysicalOutcome::Unavailable),
        FinalInspection::Conflict => Ok(InstalledRuntimePhysicalOutcome::Conflict),
    }
}

fn predecessor_matches_manifest(
    predecessor: &LifecycleCommandResponse,
    manifest: &InstalledRuntimeManifest,
) -> bool {
    if predecessor.cat_id != manifest.cat_id
        || predecessor.node_id != manifest.node_id
        || predecessor.placement_identity != manifest.placement_identity
    {
        return false;
    }
    match &predecessor.result {
        NodeResult::RuntimeReady(ready) => {
            predecessor.operation_id == manifest.source_lifecycle_operation_id
                && ready.runtime_incarnation == manifest.runtime_incarnation
                && ready.runtime_config_digest == manifest.runtime_config_digest
                && ready.execution_receipt_digest == manifest.execution_receipt_digest
                && ready.guest_ready_receipt_digest == manifest.guest_ready_receipt_digest
        }
        NodeResult::SuspendDeclined(declined) => {
            declined
                .effective_runtime_ready
                .source_lifecycle_operation_id
                == manifest.source_lifecycle_operation_id
                && declined.effective_runtime_ready.runtime_incarnation
                    == manifest.runtime_incarnation
                && declined.effective_runtime_ready.runtime_config_digest
                    == manifest.runtime_config_digest
                && declined
                    .effective_runtime_ready
                    .runtime_ready_receipt_digest
                    == manifest.execution_receipt_digest
        }
        NodeResult::Suspended(suspended) => {
            suspended.runtime_incarnation == manifest.runtime_incarnation
                && suspended.runtime_config_digest == manifest.runtime_config_digest
        }
        NodeResult::NeedsIntervention(intervention) => {
            intervention.retained_volume_receipts.iter().all(|receipt| {
                manifest.volumes.iter().any(|volume| {
                    volume.volume_id == receipt.volume_id
                        && volume.attachment_id == receipt.attachment_id
                        && volume.attachment_epoch == receipt.attachment_epoch
                })
            })
        }
        _ => false,
    }
}

enum FinalInspection {
    Exact {
        vmm_state: InstalledPhysicalVmmState,
        volume_receipts: Vec<VolumeTerminalReceipt>,
        physical_identity_digest: Sha256Digest,
    },
    Absent {
        physical_identity_digest: Sha256Digest,
    },
    Unavailable,
    Conflict,
}

fn inspect_final_manifest(
    config: &InstalledPhysicalInspectionConfig,
    inputs: &PhysicalInputs,
    manifest: &InstalledRuntimeManifest,
    read: &ReadDeadline,
) -> Result<FinalInspection> {
    read.check_active()?;
    if !manifest_is_internally_closed(manifest) {
        return Ok(FinalInspection::Conflict);
    }
    let cgroup = match scan_exact_cgroup_tree(
        &config.cgroup_root,
        &config.proc_root,
        &manifest.cat_id,
        &config.managed_process_binaries,
    ) {
        Ok(cgroup) => cgroup,
        Err(_) => return Ok(FinalInspection::Conflict),
    };
    let vmm_process = match inspect_process(
        &config.proc_root,
        &manifest.vmm.process,
        Path::new(
            manifest
                .vmm
                .launch_identity
                .boot
                .vmm_executable
                .path
                .as_str(),
        ),
        &cat_service_control_group(&manifest.cat_id, &manifest.vmm.systemd_unit_id),
    ) {
        Ok(state) => state,
        Err(_) => return Ok(FinalInspection::Conflict),
    };
    if vmm_process == ExactProcessState::Absent {
        for volume in &manifest.volumes {
            let Some(authority) = inputs.authority.get(&volume.volume_id) else {
                return Ok(FinalInspection::Conflict);
            };
            let Some(binding) = authority.binding.as_ref() else {
                return Ok(FinalInspection::Conflict);
            };
            if binding.owner_node_id != manifest.node_id
                || binding.attachment_id != volume.attachment_id
                || binding.attachment_epoch != volume.attachment_epoch
                || volume.authority_receipt_digest.is_none()
                || authority.volume.head.generation < volume.launch_head.generation
            {
                return Ok(FinalInspection::Conflict);
            }
            if !volume_frontend_is_absent(config, volume)? {
                return Ok(FinalInspection::Conflict);
            }
        }
        if cgroup.slice_present || !cgroup.process_ids.is_empty() {
            return Ok(FinalInspection::Conflict);
        }
        return Ok(FinalInspection::Absent {
            physical_identity_digest: physical_join_digest(
                manifest,
                &cgroup.canonical_digest,
                &[],
                "absent",
            ),
        });
    }

    let vmm_state = match inspect_installed_vmm_api(
        &manifest.vmm.launch_identity,
        manifest.vmm.process.pid,
        read,
    )? {
        InstalledVmmApiInspection::Exact {
            state: ProcessState::Running,
        } => InstalledPhysicalVmmState::Executing,
        InstalledVmmApiInspection::Exact {
            state: ProcessState::Paused,
        } => InstalledPhysicalVmmState::Paused,
        InstalledVmmApiInspection::Unavailable => return Ok(FinalInspection::Unavailable),
        InstalledVmmApiInspection::Conflict => return Ok(FinalInspection::Conflict),
    };
    match inputs
        .networks
        .reserved_network_state(&manifest.network.identity)?
    {
        ReservedHostNetworkState::Exact => {}
        ReservedHostNetworkState::Absent => return Ok(FinalInspection::Conflict),
    }

    let mut volume_receipts = Vec::with_capacity(manifest.volumes.len());
    for volume in &manifest.volumes {
        let Some(authority) = inputs.authority.get(&volume.volume_id) else {
            return Ok(FinalInspection::Conflict);
        };
        match inspect_live_volume(config, manifest, volume, authority, read)? {
            LiveVolumeInspection::Exact(receipt) => volume_receipts.push(receipt),
            LiveVolumeInspection::Unavailable => return Ok(FinalInspection::Unavailable),
            LiveVolumeInspection::Conflict => return Ok(FinalInspection::Conflict),
        }
    }
    volume_receipts.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    if !volume_receipts
        .windows(2)
        .all(|pair| pair[0].volume_id < pair[1].volume_id)
    {
        return Ok(FinalInspection::Conflict);
    }
    let state = match vmm_state {
        InstalledPhysicalVmmState::Executing => "executing",
        InstalledPhysicalVmmState::Paused => "paused",
    };
    Ok(FinalInspection::Exact {
        vmm_state,
        physical_identity_digest: physical_join_digest(
            manifest,
            &cgroup.canonical_digest,
            &volume_receipts,
            state,
        ),
        volume_receipts,
    })
}

fn manifest_is_internally_closed(manifest: &InstalledRuntimeManifest) -> bool {
    let launch = manifest.vmm.launch_identity.as_ref();
    manifest.vmm.parent_slice_id == cat_execution_slice_id(&manifest.cat_id)
        && manifest.vmm.systemd_unit_id == launch.scope_id
        && manifest.vmm.api_socket_path == launch.api_socket_path
        && manifest.vmm.vsock_socket_path == launch.vsock_socket_path
        && manifest.vmm.memory_file_path == launch.memory_file_path
        && manifest.runtime_incarnation == launch.runtime_incarnation
        && manifest.network.identity.as_ref() == launch.network.as_ref()
        && manifest.volumes.len() == launch.devices.len()
        && manifest.volumes.iter().all(|volume| {
            launch.devices.iter().any(|device| {
                device.volume_id == volume.volume_id
                    && device.disk_id == volume.disk_id
                    && device.attachment_id == volume.attachment_id
                    && device.attachment_epoch == volume.attachment_epoch
                    && device.serving_process.data_directory == volume.local_lineage_data_directory
                    && device.serving_process.control_socket_path
                        == volume.blockd_control_socket_path
            })
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactProcessState {
    Present,
    Absent,
}

fn inspect_process(
    proc_root: &Path,
    identity: &InstalledRuntimeProcessIdentity,
    expected_executable: &Path,
    expected_cgroup: &str,
) -> Result<ExactProcessState> {
    let directory = proc_root.join(identity.pid.to_string());
    let stat = match fs::read_to_string(directory.join("stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(ExactProcessState::Absent),
        Err(error) => return Err(error).context("read installed process start identity"),
    };
    let Some(start_ticks) = crate::proc::parse_start_ticks(&stat) else {
        anyhow::bail!("installed process stat is malformed")
    };
    if start_ticks != identity.start_time_ticks.get() {
        return Ok(ExactProcessState::Absent);
    }
    let executable =
        fs::read_link(directory.join("exe")).context("read exact installed process executable")?;
    anyhow::ensure!(
        executable == expected_executable,
        "installed process executable changed"
    );
    let cgroup = read_unified_process_cgroup(proc_root, identity.pid)?;
    anyhow::ensure!(
        cgroup == expected_cgroup,
        "installed process left its exact Cat child service"
    );
    Ok(ExactProcessState::Present)
}

enum LiveVolumeInspection {
    Exact(VolumeTerminalReceipt),
    Unavailable,
    Conflict,
}

fn inspect_live_volume(
    config: &InstalledPhysicalInspectionConfig,
    manifest: &InstalledRuntimeManifest,
    volume: &InstalledRuntimeVolumeManifest,
    authority: &NodeVolumeInventoryRecord,
    read: &ReadDeadline,
) -> Result<LiveVolumeInspection> {
    let Some(binding) = &authority.binding else {
        return Ok(LiveVolumeInspection::Conflict);
    };
    if binding.owner_node_id != manifest.node_id
        || binding.attachment_id != volume.attachment_id
        || binding.attachment_epoch != volume.attachment_epoch
        || volume.authority_receipt_digest.is_none()
    {
        return Ok(LiveVolumeInspection::Conflict);
    }
    let Some(device) = manifest
        .vmm
        .launch_identity
        .devices
        .iter()
        .find(|device| device.volume_id == volume.volume_id)
    else {
        return Ok(LiveVolumeInspection::Conflict);
    };
    match inspect_process(
        &config.proc_root,
        &volume.blockd,
        Path::new(device.serving_process.executable_path.as_str()),
        &cat_service_control_group(&manifest.cat_id, &device.serving_process.scope_id),
    ) {
        Ok(ExactProcessState::Present) => {}
        Ok(ExactProcessState::Absent) | Err(_) => return Ok(LiveVolumeInspection::Conflict),
    }
    if !frontend_is_exact(config, &manifest.cat_id, volume)? {
        return Ok(LiveVolumeInspection::Conflict);
    }
    let status = match blockd_status(
        Path::new(volume.blockd_control_socket_path.as_str()),
        volume.blockd.pid,
        read,
    ) {
        Ok(status) => status,
        Err(error)
            if error.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(io.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
            }) =>
        {
            return Ok(LiveVolumeInspection::Unavailable)
        }
        Err(_) => return Ok(LiveVolumeInspection::Conflict),
    };
    if status.volume_id != volume.volume_id.as_str()
        || status.attachment_id != volume.attachment_id.as_str()
        || status.attachment_epoch.as_ref() != Some(&volume.attachment_epoch)
        || status.node_id.as_ref() != Some(&manifest.node_id)
        || status.placement_epoch != Some(manifest.placement_identity.placement_epoch)
        || status.size_bytes != Some(authority.volume.size_bytes)
        || status.scope_id.as_ref() != Some(&device.serving_process.scope_id)
        || status.process_identity_token.as_ref()
            != Some(&device.serving_process.process_identity_token)
        || status.guest_device_serial.as_ref() != Some(&device.guest_device.serial)
        || status.remote_head.as_ref() != Some(&authority.volume.head)
        || status.fenced
        || status.local_durable_generation < 0
        || status.remote_durable_generation < 0
        || status.remote_durable_generation > status.local_durable_generation
    {
        return Ok(LiveVolumeInspection::Conflict);
    }
    let local = Generation::new(status.local_durable_generation as u64)
        .context("blockd local generation is outside the wire domain")?;
    let remote = Generation::new(status.remote_durable_generation as u64)
        .context("blockd remote generation is outside the wire domain")?;
    if remote != authority.volume.head.generation {
        return Ok(LiveVolumeInspection::Conflict);
    }
    Ok(LiveVolumeInspection::Exact(VolumeTerminalReceipt {
        volume_id: volume.volume_id.clone(),
        disk_id: volume.disk_id.clone(),
        disk_role: volume.disk_role,
        attachment_id: volume.attachment_id.clone(),
        attachment_epoch: volume.attachment_epoch,
        local_durable_generation: local,
        remote_durable_generation: remote,
        authority_receipt_digest: volume.authority_receipt_digest.clone(),
    }))
}

fn frontend_is_exact(
    config: &InstalledPhysicalInspectionConfig,
    cat_id: &Id,
    volume: &InstalledRuntimeVolumeManifest,
) -> Result<bool> {
    match &volume.frontend {
        InstalledRuntimeBlockFrontend::KernelNbd {
            device_path,
            client,
        } => {
            let Some(kernel) = &config.kernel_nbd else {
                return Ok(false);
            };
            let slots = scan_kernel_nbd_pool(kernel, &config.proc_root)?;
            let exact = slots.iter().any(|slot| {
                matches!(slot,
                    KernelNbdSlot::Serving { device_path: observed, process_id }
                        if observed == Path::new(device_path.as_str()) && *process_id == client.pid)
            });
            if !exact {
                return Ok(false);
            }
            let cgroup = read_unified_process_cgroup(&config.proc_root, client.pid)?;
            let stat =
                fs::read_to_string(config.proc_root.join(client.pid.to_string()).join("stat"))?;
            Ok(
                crate::proc::parse_start_ticks(&stat) == Some(client.start_time_ticks.get())
                    && (cgroup == format!("/{}", cat_execution_slice_id(cat_id))
                        || cgroup.starts_with(&format!("/{}/", cat_execution_slice_id(cat_id)))),
            )
        }
        InstalledRuntimeBlockFrontend::VhostUserBlk { socket_path } => {
            match fs::symlink_metadata(Path::new(socket_path.as_str())) {
                Ok(metadata) => {
                    Ok(metadata.file_type().is_socket() && !metadata.file_type().is_symlink())
                }
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error).context("inspect exact vhost-user frontend"),
            }
        }
    }
}

fn volume_frontend_is_absent(
    config: &InstalledPhysicalInspectionConfig,
    volume: &InstalledRuntimeVolumeManifest,
) -> Result<bool> {
    match &volume.frontend {
        InstalledRuntimeBlockFrontend::KernelNbd { device_path, .. } => {
            let Some(kernel) = &config.kernel_nbd else {
                return Ok(false);
            };
            Ok(scan_kernel_nbd_pool(kernel, &config.proc_root)?
                .iter()
                .find(|slot| slot.device_path() == Path::new(device_path.as_str()))
                .is_some_and(|slot| !slot.is_live()))
        }
        InstalledRuntimeBlockFrontend::VhostUserBlk { socket_path } => {
            match fs::symlink_metadata(Path::new(socket_path.as_str())) {
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
                Ok(_) => Ok(false),
                Err(error) => Err(error).context("inspect stopped vhost-user frontend"),
            }
        }
    }
}

fn blockd_status(
    socket_path: &Path,
    expected_peer_pid: u32,
    read: &ReadDeadline,
) -> Result<DurabilityStatus> {
    read.check_active()?;
    let before = fs::symlink_metadata(socket_path).context("inspect blockd control socket")?;
    anyhow::ensure!(
        before.file_type().is_socket() && !before.file_type().is_symlink(),
        "blockd control path is not an exact Unix socket"
    );
    let mut stream = UnixStream::connect(socket_path).context("connect blockd control socket")?;
    ensure_peer_process(&stream, expected_peer_pid)?;
    let remaining = read
        .deadline()
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .context("blockd control deadline elapsed")?;
    stream.set_write_timeout(Some(remaining.min(Duration::from_millis(500))))?;
    stream.set_read_timeout(Some(CONTROL_POLL_INTERVAL.min(remaining)))?;
    stream.write_all(BlockdControlCommand::Status.as_wire().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut line = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    loop {
        read.check_active()?;
        anyhow::ensure!(
            line.len() < BLOCKD_CONTROL_MAX_LINE_BYTES,
            "blockd control response exceeds its fixed bound"
        );
        match stream.read(&mut byte) {
            Ok(0) => anyhow::bail!("blockd control response ended before newline"),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                continue
            }
            Err(error) => return Err(error).context("read blockd control response"),
        }
    }
    ensure_peer_process(&stream, expected_peer_pid)?;
    let after = fs::symlink_metadata(socket_path).context("reinspect blockd control socket")?;
    anyhow::ensure!(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "blockd control socket changed during status"
    );
    let line = std::str::from_utf8(&line).context("blockd response is not UTF-8")?;
    let payload = match BlockdControlResponse::parse_wire(line) {
        Ok(BlockdControlResponse::Ok(payload)) => payload,
        Ok(BlockdControlResponse::Error(_)) => anyhow::bail!("blockd status was rejected"),
        Err(error) => return Err(error).context("decode blockd control response"),
    };
    serde_json::from_str(&payload).context("decode bounded blockd status")
}

#[cfg(target_os = "linux")]
fn ensure_peer_process(stream: &UnixStream, expected_process_id: u32) -> Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: both output objects are writable for the exact lengths supplied,
    // and `stream` retains the descriptor for the duration of getsockopt.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    anyhow::ensure!(
        result == 0
            && length as usize == std::mem::size_of::<libc::ucred>()
            && credentials.pid > 0
            && u32::try_from(credentials.pid).ok() == Some(expected_process_id),
        "blockd control peer is not the exact installed process"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_peer_process(_stream: &UnixStream, _expected_process_id: u32) -> Result<()> {
    anyhow::bail!("exact blockd peer credentials require Linux")
}

fn project_final_manifest(
    config: &InstalledPhysicalInspectionConfig,
    inputs: &PhysicalInputs,
    manifest: &InstalledRuntimeManifest,
    read: &ReadDeadline,
) -> Result<ObservedCatRuntimeTelemetry> {
    match inspect_final_manifest(config, inputs, manifest, read)? {
        FinalInspection::Exact {
            vmm_state,
            volume_receipts,
            physical_identity_digest,
        } => {
            let mut artifacts = manifest_artifacts(manifest, true)?;
            artifacts.push(ObservedArtifactClassification::AdoptableCatState {
                artifact_id: artifact_id("physical-runtime", manifest.cat_id.as_str().as_bytes())?,
                ownership_digest: physical_identity_digest.clone(),
            });
            sort_artifacts(&mut artifacts);
            Ok(ObservedCatRuntimeTelemetry {
                cat_id: manifest.cat_id.clone(),
                observed_placement: manifest.placement_identity.clone(),
                observed_command_journal: None,
                observed_physical_state: match vmm_state {
                    InstalledPhysicalVmmState::Executing => ObservedRuntimePhysicalState::Executing,
                    InstalledPhysicalVmmState::Paused => ObservedRuntimePhysicalState::Paused,
                },
                observed_runtime_incarnation: Some(manifest.runtime_incarnation.clone()),
                observed_artifact_manifest_digest: physical_identity_digest,
                observed_artifact_classifications: artifacts,
                observed_volumes: volume_receipts
                    .iter()
                    .map(|receipt| receipt_observation(&manifest.node_id, receipt))
                    .collect(),
                observed_conditions: vec![condition(
                    ObservedRuntimeConditionKind::Healthy,
                    &manifest.manifest_digest,
                )],
            })
        }
        FinalInspection::Absent {
            physical_identity_digest,
        } => Ok(ObservedCatRuntimeTelemetry {
            cat_id: manifest.cat_id.clone(),
            observed_placement: manifest.placement_identity.clone(),
            observed_command_journal: None,
            observed_physical_state: ObservedRuntimePhysicalState::Absent,
            observed_runtime_incarnation: None,
            observed_artifact_manifest_digest: physical_identity_digest,
            observed_artifact_classifications: manifest_artifacts(manifest, false)?,
            observed_volumes: authority_observations(inputs, manifest),
            observed_conditions: Vec::new(),
        }),
        FinalInspection::Unavailable => {
            anyhow::bail!("installed runtime physical provider is unavailable")
        }
        FinalInspection::Conflict => ambiguous_final_projection(manifest),
    }
}

fn project_progress_manifest(
    config: &InstalledPhysicalInspectionConfig,
    inputs: &PhysicalInputs,
    manifest: &InstalledRuntimeProgressManifest,
    read: &ReadDeadline,
) -> Result<ObservedCatRuntimeTelemetry> {
    read.check_active()?;
    let cgroup = scan_exact_cgroup_tree(
        &config.cgroup_root,
        &config.proc_root,
        &manifest.cat_id,
        &config.managed_process_binaries,
    );
    let (state, incarnation, condition_kind) = match (&manifest.vmm, cgroup.as_ref()) {
        (Some(vmm), Ok(cgroup)) => {
            match inspect_progress_vmm(config, &manifest.cat_id, vmm, read)? {
                ProgressVmmInspection::Exact(InstalledPhysicalVmmState::Executing) => (
                    ObservedRuntimePhysicalState::Executing,
                    Some(manifest.runtime_incarnation.clone()),
                    ObservedRuntimeConditionKind::Progressing,
                ),
                ProgressVmmInspection::Exact(InstalledPhysicalVmmState::Paused) => (
                    ObservedRuntimePhysicalState::Paused,
                    Some(manifest.runtime_incarnation.clone()),
                    ObservedRuntimeConditionKind::Progressing,
                ),
                ProgressVmmInspection::Absent if !cgroup.slice_present => (
                    ObservedRuntimePhysicalState::StoppedRetained,
                    None,
                    ObservedRuntimeConditionKind::Progressing,
                ),
                ProgressVmmInspection::Absent | ProgressVmmInspection::Conflict => (
                    ObservedRuntimePhysicalState::Ambiguous,
                    None,
                    ObservedRuntimeConditionKind::Quarantined,
                ),
            }
        }
        (None, Ok(scan)) if !scan.slice_present => (
            ObservedRuntimePhysicalState::StoppedRetained,
            None,
            ObservedRuntimeConditionKind::Progressing,
        ),
        _ => (
            ObservedRuntimePhysicalState::Ambiguous,
            None,
            ObservedRuntimeConditionKind::Quarantined,
        ),
    };
    let digest = progress_physical_digest(manifest, state);
    // Executing progress is attribution, never a restart/admission source.
    // In particular, a crash after a physical leaf but before RuntimeReady
    // must not let a previously labelled leaf artifact manufacture an
    // adoptable Cat. GC candidates are retained too while their owning Start
    // operation is still unresolved.
    let mut artifacts = manifest
        .artifact_classifications
        .iter()
        .map(non_adoptable_progress_artifact)
        .collect::<Vec<_>>();
    artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
        artifact_id: artifact_id("atomic-start-progress", manifest.cat_id.as_str().as_bytes())?,
        evidence_digest: manifest.manifest_digest.clone(),
    });
    sort_artifacts(&mut artifacts);
    Ok(ObservedCatRuntimeTelemetry {
        cat_id: manifest.cat_id.clone(),
        observed_placement: manifest.placement_identity.clone(),
        observed_command_journal: None,
        observed_physical_state: state,
        observed_runtime_incarnation: incarnation,
        observed_artifact_manifest_digest: digest.clone(),
        observed_artifact_classifications: artifacts,
        observed_volumes: progress_authority_observations(inputs, manifest),
        observed_conditions: vec![condition(condition_kind, &digest)],
    })
}

fn non_adoptable_progress_artifact(
    artifact: &ObservedArtifactClassification,
) -> ObservedArtifactClassification {
    match artifact {
        ObservedArtifactClassification::AdoptableCatState {
            artifact_id,
            ownership_digest,
        } => ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: artifact_id.clone(),
            evidence_digest: ownership_digest.clone(),
        },
        ObservedArtifactClassification::CatOwnedGcCandidate {
            artifact_id,
            ownership_digest,
            postcondition_digest,
        } => ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: artifact_id.clone(),
            evidence_digest: digest_parts(
                PHYSICAL_JOIN_DOMAIN,
                &[
                    b"unresolved-gc-candidate",
                    artifact_id.as_str().as_bytes(),
                    ownership_digest.as_bytes(),
                    postcondition_digest.as_bytes(),
                ],
            ),
        },
        ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id,
            evidence_digest,
        } => ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: artifact_id.clone(),
            evidence_digest: evidence_digest.clone(),
        },
        ObservedArtifactClassification::QuarantinedForeignOrAmbiguous {
            artifact_id,
            evidence_digest,
        } => ObservedArtifactClassification::QuarantinedForeignOrAmbiguous {
            artifact_id: artifact_id.clone(),
            evidence_digest: evidence_digest.clone(),
        },
    }
}

fn project_terminal_retained_manifests(
    config: &InstalledPhysicalInspectionConfig,
    inputs: &PhysicalInputs,
    manifests: &[TerminalRetainedRuntimeManifest],
    read: &ReadDeadline,
) -> Result<ObservedCatRuntimeTelemetry> {
    let first = manifests
        .first()
        .context("terminal retained projection is empty")?;
    read.check_active()?;
    let same_identity = manifests.iter().all(|manifest| {
        manifest.cat_id == first.cat_id
            && manifest.node_id == first.node_id
            && manifest.placement_identity == first.placement_identity
    });
    let cgroup = scan_exact_cgroup_tree(
        &config.cgroup_root,
        &config.proc_root,
        &first.cat_id,
        &config.managed_process_binaries,
    );
    let exact_absence = same_identity
        && cgroup.as_ref().is_ok_and(|scan| !scan.slice_present)
        && manifests.iter().all(|manifest| {
            manifest.runtime_progress.as_ref().is_none_or(|progress| {
                progress
                    .volumes
                    .iter()
                    .all(|volume| progress_frontend_is_absent(config, volume).unwrap_or(false))
            })
        });
    let (observed_volumes, observations_closed) = terminal_retained_observations(inputs, manifests);
    let cgroup_digest = cgroup
        .as_ref()
        .ok()
        .map(|scan| scan.canonical_digest.clone());
    let digest = terminal_retained_physical_digest(
        manifests,
        cgroup_digest.as_ref(),
        &observed_volumes,
        exact_absence && observations_closed,
    );
    let mut artifacts = terminal_retained_artifacts(manifests)?;
    let (state, condition_kind) = if exact_absence && observations_closed {
        (
            ObservedRuntimePhysicalState::StoppedRetained,
            ObservedRuntimeConditionKind::Blocked,
        )
    } else {
        artifacts.push(quarantined_artifact(
            "terminal-retained-physical-conflict",
            first.cat_id.as_str().as_bytes(),
        )?);
        (
            ObservedRuntimePhysicalState::Ambiguous,
            ObservedRuntimeConditionKind::Quarantined,
        )
    };
    sort_artifacts(&mut artifacts);
    Ok(ObservedCatRuntimeTelemetry {
        cat_id: first.cat_id.clone(),
        observed_placement: first.placement_identity.clone(),
        observed_command_journal: None,
        observed_physical_state: state,
        observed_runtime_incarnation: None,
        observed_artifact_manifest_digest: digest.clone(),
        observed_artifact_classifications: artifacts,
        observed_volumes,
        observed_conditions: vec![condition(condition_kind, &digest)],
    })
}

fn overlay_terminal_retained_manifests(
    manifests: &[TerminalRetainedRuntimeManifest],
    projection: &mut ObservedCatRuntimeTelemetry,
) -> Result<()> {
    if manifests.is_empty() {
        return Ok(());
    }
    let contradicts_execution = projection
        .observed_runtime_incarnation
        .as_ref()
        .is_some_and(|incarnation| {
            manifests
                .iter()
                .any(|manifest| &manifest.runtime_incarnation == incarnation)
        });
    let prior = projection.observed_artifact_manifest_digest.clone();
    let retained_digest = terminal_retained_physical_digest(manifests, None, &[], true);
    let digest = digest_parts(
        PHYSICAL_JOIN_DOMAIN,
        &[
            b"with-terminal-retained",
            prior.as_bytes(),
            retained_digest.as_bytes(),
        ],
    );
    projection.observed_artifact_manifest_digest = digest.clone();
    projection
        .observed_artifact_classifications
        .extend(terminal_retained_artifacts(manifests)?);
    if contradicts_execution {
        projection.observed_physical_state = ObservedRuntimePhysicalState::Ambiguous;
        projection.observed_runtime_incarnation = None;
        projection
            .observed_artifact_classifications
            .push(quarantined_artifact(
                "terminal-retained-execution-conflict",
                projection.cat_id.as_str().as_bytes(),
            )?);
        projection.observed_conditions = vec![condition(
            ObservedRuntimeConditionKind::Quarantined,
            &digest,
        )];
    } else if projection.observed_physical_state == ObservedRuntimePhysicalState::Absent {
        projection.observed_physical_state = ObservedRuntimePhysicalState::StoppedRetained;
        projection.observed_conditions =
            vec![condition(ObservedRuntimeConditionKind::Blocked, &digest)];
    } else {
        for condition in &mut projection.observed_conditions {
            condition.evidence_digest = digest.clone();
        }
    }
    sort_artifacts(&mut projection.observed_artifact_classifications);
    Ok(())
}

fn progress_frontend_is_absent(
    config: &InstalledPhysicalInspectionConfig,
    volume: &super::start::InstalledRuntimeProgressVolumeManifest,
) -> Result<bool> {
    let Some(frontend) = &volume.frontend else {
        return Ok(true);
    };
    match frontend {
        InstalledRuntimeBlockFrontend::KernelNbd { device_path, .. } => {
            let Some(kernel) = &config.kernel_nbd else {
                return Ok(false);
            };
            Ok(scan_kernel_nbd_pool(kernel, &config.proc_root)?
                .iter()
                .find(|slot| slot.device_path() == Path::new(device_path.as_str()))
                .is_some_and(|slot| !slot.is_live()))
        }
        InstalledRuntimeBlockFrontend::VhostUserBlk { socket_path } => {
            match fs::symlink_metadata(Path::new(socket_path.as_str())) {
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
                Ok(_) => Ok(false),
                Err(error) => Err(error).context("inspect terminal retained frontend"),
            }
        }
    }
}

fn terminal_retained_observations(
    inputs: &PhysicalInputs,
    manifests: &[TerminalRetainedRuntimeManifest],
) -> (Vec<ObservedVolumeWatermarkSummary>, bool) {
    let mut observations = BTreeMap::new();
    let mut closed = true;
    for manifest in manifests {
        for receipt in &manifest.retained_volume_receipts {
            let Some(authority) = inputs.authority.get(&receipt.volume_id) else {
                closed = false;
                continue;
            };
            let manifest_binding_exact = match &manifest.retention_mode {
                TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } => evidence
                    .volumes
                    .iter()
                    .find(|volume| volume.retained_receipt.volume_id == receipt.volume_id)
                    .is_some_and(|volume| {
                        volume.retained_receipt == *receipt
                            && receipt.authority_receipt_digest.as_ref()
                                == Some(&volume.immutable_start_grant_receipt_digest)
                            && volume.authoritative_head.generation
                                == receipt.remote_durable_generation
                    }),
                TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation { .. }
                | TerminalRetainedRuntimeMode::MaterializedOrAmbiguous => manifest
                    .runtime_progress
                    .as_ref()
                    .and_then(|progress| {
                        progress
                            .volumes
                            .iter()
                            .find(|volume| volume.volume_id == receipt.volume_id)
                    })
                    .is_some_and(|volume| {
                        receipt.disk_id == volume.disk_id
                            && receipt.disk_role == volume.disk_role
                            && receipt.attachment_id == volume.attachment_id
                            && receipt.attachment_epoch == volume.attachment_epoch
                            && receipt.authority_receipt_digest == volume.authority_receipt_digest
                    }),
            };
            let observation = if let Some(binding) = authority.binding.as_ref() {
                let exact = manifest_binding_exact
                    && binding.owner_node_id == manifest.node_id
                    && binding.attachment_id == receipt.attachment_id
                    && binding.attachment_epoch == receipt.attachment_epoch
                    && receipt.authority_receipt_digest.is_some()
                    && receipt.remote_durable_generation == authority.volume.head.generation
                    && receipt.remote_durable_generation <= receipt.local_durable_generation;
                if exact {
                    receipt_observation(&manifest.node_id, receipt)
                } else {
                    closed = false;
                    unknown_watermark_observation(
                        &receipt.volume_id,
                        &receipt.disk_id,
                        receipt.disk_role,
                        authority,
                    )
                }
            } else {
                closed = false;
                unknown_watermark_observation(
                    &receipt.volume_id,
                    &receipt.disk_id,
                    receipt.disk_role,
                    authority,
                )
            };
            if observations
                .insert(receipt.volume_id.clone(), observation.clone())
                .is_some_and(|previous| previous != observation)
            {
                closed = false;
            }
        }
    }
    (observations.into_values().collect(), closed)
}

fn terminal_retained_artifacts(
    manifests: &[TerminalRetainedRuntimeManifest],
) -> Result<Vec<ObservedArtifactClassification>> {
    let mut artifacts = Vec::new();
    for manifest in manifests {
        artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: artifact_id(
                "terminal-retained-start",
                manifest.manifest_digest.as_bytes(),
            )?,
            evidence_digest: manifest.manifest_digest.clone(),
        });
        artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: artifact_id(
                "terminal-retained-physical-evidence",
                manifest
                    .physical_retained_evidence
                    .artifact_manifest_digest
                    .as_bytes(),
            )?,
            evidence_digest: manifest
                .physical_retained_evidence
                .artifact_manifest_digest
                .clone(),
        });
        if let Some(progress) = &manifest.runtime_progress {
            for artifact in &progress.artifact_classifications {
                artifacts.push(non_adoptable_progress_artifact(artifact));
            }
        }
        if let TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } =
            &manifest.retention_mode
        {
            artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
                artifact_id: artifact_id(
                    "inherited-predecessor-physical",
                    evidence.predecessor_physical_manifest_digest.as_bytes(),
                )?,
                evidence_digest: evidence.predecessor_physical_manifest_digest.clone(),
            });
        }
    }
    sort_artifacts(&mut artifacts);
    Ok(artifacts)
}

fn terminal_retained_physical_digest(
    manifests: &[TerminalRetainedRuntimeManifest],
    cgroup_digest: Option<&Sha256Digest>,
    volumes: &[ObservedVolumeWatermarkSummary],
    exact_absence: bool,
) -> Sha256Digest {
    let canonical =
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&serde_json::json!({
            "version": 1,
            "manifest_digests": manifests
                .iter()
                .map(|manifest| &manifest.manifest_digest)
                .collect::<Vec<_>>(),
            "cgroup_digest": cgroup_digest,
            "exact_absence": exact_absence,
            "volumes": volumes,
        }));
    digest_parts(PHYSICAL_JOIN_DOMAIN, &[b"terminal-retained", &canonical])
}

enum ProgressVmmInspection {
    Exact(InstalledPhysicalVmmState),
    Absent,
    Conflict,
}

fn inspect_progress_vmm(
    config: &InstalledPhysicalInspectionConfig,
    cat_id: &Id,
    vmm: &InstalledRuntimeVmmManifest,
    read: &ReadDeadline,
) -> Result<ProgressVmmInspection> {
    if inspect_process(
        &config.proc_root,
        &vmm.process,
        Path::new(vmm.launch_identity.boot.vmm_executable.path.as_str()),
        &cat_service_control_group(cat_id, &vmm.systemd_unit_id),
    )? == ExactProcessState::Absent
    {
        return Ok(ProgressVmmInspection::Absent);
    }
    Ok(
        match inspect_installed_vmm_api(&vmm.launch_identity, vmm.process.pid, read)? {
            InstalledVmmApiInspection::Exact {
                state: ProcessState::Running,
            } => ProgressVmmInspection::Exact(InstalledPhysicalVmmState::Executing),
            InstalledVmmApiInspection::Exact {
                state: ProcessState::Paused,
            } => ProgressVmmInspection::Exact(InstalledPhysicalVmmState::Paused),
            InstalledVmmApiInspection::Unavailable => {
                anyhow::bail!("atomic Start VMM inspection is unavailable")
            }
            InstalledVmmApiInspection::Conflict => ProgressVmmInspection::Conflict,
        },
    )
}

fn conflicting_manifest_projection(
    final_manifest: Option<&InstalledRuntimeManifest>,
    progress: &[InstalledRuntimeProgressManifest],
) -> Result<ObservedCatRuntimeTelemetry> {
    let (cat_id, placement, digests) = if let Some(manifest) = final_manifest {
        (
            manifest.cat_id.clone(),
            manifest.placement_identity.clone(),
            std::iter::once(&manifest.manifest_digest)
                .chain(progress.iter().map(|progress| &progress.manifest_digest))
                .collect::<Vec<_>>(),
        )
    } else {
        let first = progress
            .first()
            .context("conflicting progress projection is empty")?;
        (
            first.cat_id.clone(),
            first.placement_identity.clone(),
            progress
                .iter()
                .map(|progress| &progress.manifest_digest)
                .collect::<Vec<_>>(),
        )
    };
    let digest = digest_parts(
        PHYSICAL_JOIN_DOMAIN,
        &digests
            .iter()
            .map(|digest| digest.as_bytes().as_slice())
            .collect::<Vec<_>>(),
    );
    Ok(ObservedCatRuntimeTelemetry {
        cat_id: cat_id.clone(),
        observed_placement: placement,
        observed_command_journal: None,
        observed_physical_state: ObservedRuntimePhysicalState::Ambiguous,
        observed_runtime_incarnation: None,
        observed_artifact_manifest_digest: digest.clone(),
        observed_artifact_classifications: vec![quarantined_artifact(
            "conflicting-runtime-manifests",
            cat_id.as_str().as_bytes(),
        )?],
        observed_volumes: Vec::new(),
        observed_conditions: vec![condition(
            ObservedRuntimeConditionKind::Quarantined,
            &digest,
        )],
    })
}

fn warm_only_ambiguous_projection(
    cat_id: &Id,
    terminals: Option<&[InstalledWarmSnapshotArtifact]>,
    prepared: Option<&[InstalledPreparedWarmSnapshotArtifact]>,
    intents: Option<&[InstalledWarmSnapshotIntentArtifact]>,
) -> Result<ObservedCatRuntimeTelemetry> {
    let terminals = terminals.unwrap_or_default();
    let prepared = prepared.unwrap_or_default();
    let intents = intents.unwrap_or_default();
    let placement = terminals
        .first()
        .map(|artifact| artifact.placement_identity.clone())
        .or_else(|| {
            prepared
                .first()
                .map(|artifact| artifact.placement_identity.clone())
        })
        .or_else(|| {
            intents
                .first()
                .map(|artifact| artifact.placement_identity.clone())
        })
        .context("Warm-only projection has no artifact")?;
    let canonical =
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&serde_json::json!({
            "version": 1,
            "cat_id": cat_id,
            "terminal_manifests": terminals
                .iter()
                .map(|artifact| &artifact.terminal_manifest_digest)
                .collect::<Vec<_>>(),
            "prepared_manifests": prepared
                .iter()
                .map(|artifact| &artifact.prepared_manifest_digest)
                .collect::<Vec<_>>(),
            "intent_manifests": intents
                .iter()
                .map(|artifact| &artifact.intent_manifest_digest)
                .collect::<Vec<_>>(),
        }));
    let digest = digest_parts(PHYSICAL_JOIN_DOMAIN, &[b"warm-without-runtime", &canonical]);
    let mut artifacts = warm_artifact_classifications(terminals, prepared, intents, false)?;
    artifacts.push(quarantined_artifact(
        "warm-without-installed-runtime",
        cat_id.as_str().as_bytes(),
    )?);
    sort_artifacts(&mut artifacts);
    Ok(ObservedCatRuntimeTelemetry {
        cat_id: cat_id.clone(),
        observed_placement: placement,
        observed_command_journal: None,
        observed_physical_state: ObservedRuntimePhysicalState::Ambiguous,
        observed_runtime_incarnation: None,
        observed_artifact_manifest_digest: digest.clone(),
        observed_artifact_classifications: artifacts,
        observed_volumes: Vec::new(),
        observed_conditions: vec![condition(
            ObservedRuntimeConditionKind::Quarantined,
            &digest,
        )],
    })
}

fn overlay_warm_artifacts(
    inputs: &PhysicalInputs,
    final_manifest: Option<&InstalledRuntimeManifest>,
    terminals: &[InstalledWarmSnapshotArtifact],
    prepared: &[InstalledPreparedWarmSnapshotArtifact],
    intents: &[InstalledWarmSnapshotIntentArtifact],
    projection: &mut ObservedCatRuntimeTelemetry,
) -> Result<()> {
    if terminals.is_empty() && prepared.is_empty() && intents.is_empty() {
        return Ok(());
    }
    let Some(manifest) = final_manifest else {
        quarantine_warm_projection(
            projection,
            terminals,
            prepared,
            intents,
            "missing-runtime-manifest",
        )?;
        return Ok(());
    };
    if terminals.len() > 1
        || prepared.len() > 1
        || intents.len() > 1
        || usize::from(!terminals.is_empty())
            + usize::from(!prepared.is_empty())
            + usize::from(!intents.is_empty())
            > 1
    {
        quarantine_warm_projection(
            projection,
            terminals,
            prepared,
            intents,
            "multiple-warm-bundles",
        )?;
        return Ok(());
    }

    if let Some(terminal) = terminals.first() {
        if projection.observed_physical_state != ObservedRuntimePhysicalState::Absent
            || !warm_terminal_matches_manifest(inputs, manifest, terminal)
        {
            quarantine_warm_projection(
                projection,
                terminals,
                prepared,
                intents,
                "warm-terminal-conflict",
            )?;
            return Ok(());
        }

        let digest =
            warm_terminal_physical_digest(&projection.observed_artifact_manifest_digest, terminal);
        projection.observed_physical_state = ObservedRuntimePhysicalState::WarmSnapshotRetained;
        projection.observed_runtime_incarnation = Some(terminal.source_runtime_incarnation.clone());
        projection.observed_artifact_manifest_digest = digest.clone();
        projection.observed_volumes = terminal
            .retained_volume_receipts
            .iter()
            .map(|receipt| receipt_observation(&manifest.node_id, receipt))
            .collect();
        projection
            .observed_artifact_classifications
            .extend(warm_artifact_classifications(
                terminals, prepared, intents, true,
            )?);
        sort_artifacts(&mut projection.observed_artifact_classifications);
        projection.observed_conditions =
            vec![condition(ObservedRuntimeConditionKind::Healthy, &digest)];
        return Ok(());
    }

    if let Some(prepared) = prepared.first() {
        if !prepared_matches_manifest(inputs, manifest, prepared) {
            quarantine_warm_projection(
                projection,
                terminals,
                std::slice::from_ref(prepared),
                intents,
                "warm-prepared-conflict",
            )?;
            return Ok(());
        }
        let digest =
            warm_prepared_physical_digest(&projection.observed_artifact_manifest_digest, prepared);
        if projection.observed_physical_state == ObservedRuntimePhysicalState::Absent {
            projection.observed_physical_state = ObservedRuntimePhysicalState::StoppedRetained;
            projection.observed_runtime_incarnation = None;
        }
        projection.observed_artifact_manifest_digest = digest.clone();
        projection
            .observed_artifact_classifications
            .extend(warm_artifact_classifications(
                terminals,
                std::slice::from_ref(prepared),
                intents,
                false,
            )?);
        sort_artifacts(&mut projection.observed_artifact_classifications);
        projection.observed_conditions = vec![condition(
            ObservedRuntimeConditionKind::Progressing,
            &digest,
        )];
        return Ok(());
    }

    let intent = intents
        .first()
        .context("Warm overlay has no terminal, prepared, or intent artifact")?;
    if !intent_matches_manifest(inputs, manifest, intent) {
        quarantine_warm_projection(
            projection,
            terminals,
            prepared,
            std::slice::from_ref(intent),
            "warm-intent-conflict",
        )?;
        return Ok(());
    }
    let digest = warm_intent_physical_digest(&projection.observed_artifact_manifest_digest, intent);
    if projection.observed_physical_state == ObservedRuntimePhysicalState::Absent {
        projection.observed_physical_state = ObservedRuntimePhysicalState::StoppedRetained;
        projection.observed_runtime_incarnation = None;
    }
    projection.observed_artifact_manifest_digest = digest.clone();
    projection
        .observed_artifact_classifications
        .extend(warm_artifact_classifications(
            terminals,
            prepared,
            std::slice::from_ref(intent),
            false,
        )?);
    sort_artifacts(&mut projection.observed_artifact_classifications);
    projection.observed_conditions = vec![condition(
        ObservedRuntimeConditionKind::Progressing,
        &digest,
    )];
    Ok(())
}

fn warm_terminal_matches_manifest(
    inputs: &PhysicalInputs,
    manifest: &InstalledRuntimeManifest,
    terminal: &InstalledWarmSnapshotArtifact,
) -> bool {
    terminal.cat_id == manifest.cat_id
        && terminal.node_id == manifest.node_id
        && terminal.placement_identity == manifest.placement_identity
        && terminal.runtime_config_id == manifest.runtime_config_id
        && terminal.runtime_config_digest == manifest.runtime_config_digest
        && terminal.source_runtime_incarnation == manifest.runtime_incarnation
        && warm_receipts_match_manifest(inputs, manifest, &terminal.retained_volume_receipts)
}

fn prepared_matches_manifest(
    inputs: &PhysicalInputs,
    manifest: &InstalledRuntimeManifest,
    prepared: &InstalledPreparedWarmSnapshotArtifact,
) -> bool {
    prepared.cat_id == manifest.cat_id
        && prepared.node_id == manifest.node_id
        && prepared.placement_identity == manifest.placement_identity
        && prepared.runtime_config_id == manifest.runtime_config_id
        && prepared.runtime_config_digest == manifest.runtime_config_digest
        && prepared.source_runtime_incarnation == manifest.runtime_incarnation
        && warm_receipts_match_manifest(inputs, manifest, &prepared.retained_volume_receipts)
}

fn intent_matches_manifest(
    inputs: &PhysicalInputs,
    manifest: &InstalledRuntimeManifest,
    intent: &InstalledWarmSnapshotIntentArtifact,
) -> bool {
    intent.cat_id == manifest.cat_id
        && intent.node_id == manifest.node_id
        && intent.placement_identity == manifest.placement_identity
        && intent.runtime_config_id == manifest.runtime_config_id
        && intent.runtime_config_digest == manifest.runtime_config_digest
        && intent.source_runtime_incarnation == manifest.runtime_incarnation
        && warm_receipts_match_manifest(inputs, manifest, &intent.retained_volume_receipts)
}

fn warm_receipts_match_manifest(
    inputs: &PhysicalInputs,
    manifest: &InstalledRuntimeManifest,
    receipts: &[VolumeTerminalReceipt],
) -> bool {
    receipts.len() == manifest.volumes.len()
        && receipts
            .windows(2)
            .all(|pair| pair[0].volume_id < pair[1].volume_id)
        && receipts.iter().all(|receipt| {
            let Some(volume) = manifest
                .volumes
                .iter()
                .find(|volume| volume.volume_id == receipt.volume_id)
            else {
                return false;
            };
            let Some(authority) = inputs.authority.get(&receipt.volume_id) else {
                return false;
            };
            let Some(binding) = authority.binding.as_ref() else {
                return false;
            };
            receipt.disk_id == volume.disk_id
                && receipt.disk_role == volume.disk_role
                && receipt.attachment_id == volume.attachment_id
                && receipt.attachment_epoch == volume.attachment_epoch
                && receipt.local_durable_generation == receipt.remote_durable_generation
                && receipt.remote_durable_generation == authority.volume.head.generation
                && receipt.remote_durable_generation >= volume.current_authority_head.generation
                && receipt.authority_receipt_digest.is_some()
                && receipt.authority_receipt_digest == volume.authority_receipt_digest
                && binding.owner_node_id == manifest.node_id
                && binding.attachment_id == receipt.attachment_id
                && binding.attachment_epoch == receipt.attachment_epoch
        })
}

fn warm_artifact_classifications(
    terminals: &[InstalledWarmSnapshotArtifact],
    prepared: &[InstalledPreparedWarmSnapshotArtifact],
    intents: &[InstalledWarmSnapshotIntentArtifact],
    terminal_is_adoptable: bool,
) -> Result<Vec<ObservedArtifactClassification>> {
    let mut artifacts = Vec::new();
    for terminal in terminals {
        let terminal_artifact_id = artifact_id(
            "warm-terminal-manifest",
            terminal.terminal_manifest_digest.as_bytes(),
        )?;
        artifacts.push(if terminal_is_adoptable {
            ObservedArtifactClassification::AdoptableCatState {
                artifact_id: terminal_artifact_id,
                ownership_digest: terminal.terminal_manifest_digest.clone(),
            }
        } else {
            ObservedArtifactClassification::RetainedAuthorityOrData {
                artifact_id: terminal_artifact_id,
                evidence_digest: terminal.terminal_manifest_digest.clone(),
            }
        });
        for (label, digest) in [
            ("warm-intent-manifest", &terminal.intent_manifest_digest),
            ("warm-prepared-manifest", &terminal.prepared_manifest_digest),
            ("warm-snapshot-tree", &terminal.snapshot_tree_digest),
            ("warm-memory-backing", &terminal.memory_file_digest),
        ] {
            artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
                artifact_id: artifact_id(label, digest.as_bytes())?,
                evidence_digest: digest.clone(),
            });
        }
    }
    for prepared in prepared {
        for (label, digest) in [
            ("warm-intent-manifest", &prepared.intent_manifest_digest),
            ("warm-prepared-manifest", &prepared.prepared_manifest_digest),
            ("warm-snapshot-tree", &prepared.snapshot_tree_digest),
            ("warm-memory-backing", &prepared.memory_file_digest),
        ] {
            artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
                artifact_id: artifact_id(label, digest.as_bytes())?,
                evidence_digest: digest.clone(),
            });
        }
    }
    for intent in intents {
        artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: artifact_id(
                "warm-intent-manifest",
                intent.intent_manifest_digest.as_bytes(),
            )?,
            evidence_digest: intent.intent_manifest_digest.clone(),
        });
        if let InstalledWarmIntentContentObservation::Present { evidence_digest } =
            &intent.content_observation
        {
            artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
                artifact_id: artifact_id("warm-intent-content", evidence_digest.as_bytes())?,
                evidence_digest: evidence_digest.clone(),
            });
        }
    }
    sort_artifacts(&mut artifacts);
    Ok(artifacts)
}

fn quarantine_warm_projection(
    projection: &mut ObservedCatRuntimeTelemetry,
    terminals: &[InstalledWarmSnapshotArtifact],
    prepared: &[InstalledPreparedWarmSnapshotArtifact],
    intents: &[InstalledWarmSnapshotIntentArtifact],
    reason: &str,
) -> Result<()> {
    let prior = projection.observed_artifact_manifest_digest.clone();
    let canonical =
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&serde_json::json!({
            "version": 1,
            "reason": reason,
            "prior_physical_digest": prior,
            "terminal_manifests": terminals
                .iter()
                .map(|artifact| &artifact.terminal_manifest_digest)
                .collect::<Vec<_>>(),
            "prepared_manifests": prepared
                .iter()
                .map(|artifact| &artifact.prepared_manifest_digest)
                .collect::<Vec<_>>(),
            "intent_manifests": intents
                .iter()
                .map(|artifact| &artifact.intent_manifest_digest)
                .collect::<Vec<_>>(),
        }));
    let digest = digest_parts(PHYSICAL_JOIN_DOMAIN, &[b"warm-conflict", &canonical]);
    projection.observed_physical_state = ObservedRuntimePhysicalState::Ambiguous;
    projection.observed_runtime_incarnation = None;
    projection.observed_artifact_manifest_digest = digest.clone();
    projection
        .observed_artifact_classifications
        .extend(warm_artifact_classifications(
            terminals, prepared, intents, false,
        )?);
    projection
        .observed_artifact_classifications
        .push(quarantined_artifact("warm-physical-conflict", &canonical)?);
    sort_artifacts(&mut projection.observed_artifact_classifications);
    projection.observed_conditions = vec![condition(
        ObservedRuntimeConditionKind::Quarantined,
        &digest,
    )];
    Ok(())
}

fn warm_terminal_physical_digest(
    prior: &Sha256Digest,
    terminal: &InstalledWarmSnapshotArtifact,
) -> Sha256Digest {
    let canonical =
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&serde_json::json!({
            "version": 1,
            "prior_physical_digest": prior,
            "terminal_manifest_digest": terminal.terminal_manifest_digest,
            "warm_receipt_digest": terminal.warm_receipt_digest,
            "intent_manifest_digest": terminal.intent_manifest_digest,
            "prepared_manifest_digest": terminal.prepared_manifest_digest,
            "snapshot_receipt_digest": terminal.snapshot_receipt_digest,
            "execution_absence": terminal.execution_absence,
            "retained_volume_receipts": terminal.retained_volume_receipts,
            "snapshot_tree_digest": terminal.snapshot_tree_digest,
            "memory_file_digest": terminal.memory_file_digest,
        }));
    digest_parts(PHYSICAL_JOIN_DOMAIN, &[b"warm-terminal", &canonical])
}

fn warm_prepared_physical_digest(
    prior: &Sha256Digest,
    prepared: &InstalledPreparedWarmSnapshotArtifact,
) -> Sha256Digest {
    let canonical =
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&serde_json::json!({
            "version": 1,
            "prior_physical_digest": prior,
            "intent_manifest_digest": prepared.intent_manifest_digest,
            "prepared_manifest_digest": prepared.prepared_manifest_digest,
            "snapshot_receipt_digest": prepared.snapshot_receipt_digest,
            "retained_volume_receipts": prepared.retained_volume_receipts,
            "snapshot_tree_digest": prepared.snapshot_tree_digest,
            "memory_file_digest": prepared.memory_file_digest,
        }));
    digest_parts(PHYSICAL_JOIN_DOMAIN, &[b"warm-prepared", &canonical])
}

fn warm_intent_physical_digest(
    prior: &Sha256Digest,
    intent: &InstalledWarmSnapshotIntentArtifact,
) -> Sha256Digest {
    let canonical =
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&serde_json::json!({
            "version": 1,
            "prior_physical_digest": prior,
            "intent_manifest_digest": intent.intent_manifest_digest,
            "snapshot_plan_digest": intent.snapshot_plan_digest,
            "retained_volume_receipts": intent.retained_volume_receipts,
            "content_observation": match &intent.content_observation {
                InstalledWarmIntentContentObservation::Absent => serde_json::json!({
                    "kind": "absent",
                }),
                InstalledWarmIntentContentObservation::Present { evidence_digest } => {
                    serde_json::json!({
                        "kind": "present",
                        "evidence_digest": evidence_digest,
                    })
                }
            },
        }));
    digest_parts(PHYSICAL_JOIN_DOMAIN, &[b"warm-intent", &canonical])
}

fn ambiguous_final_projection(
    manifest: &InstalledRuntimeManifest,
) -> Result<ObservedCatRuntimeTelemetry> {
    let digest = digest_parts(
        PHYSICAL_JOIN_DOMAIN,
        &[manifest.manifest_digest.as_bytes(), b"conflict"],
    );
    Ok(ObservedCatRuntimeTelemetry {
        cat_id: manifest.cat_id.clone(),
        observed_placement: manifest.placement_identity.clone(),
        observed_command_journal: None,
        observed_physical_state: ObservedRuntimePhysicalState::Ambiguous,
        observed_runtime_incarnation: None,
        observed_artifact_manifest_digest: digest.clone(),
        observed_artifact_classifications: vec![quarantined_artifact(
            "runtime-physical-conflict",
            manifest.cat_id.as_str().as_bytes(),
        )?],
        observed_volumes: Vec::new(),
        observed_conditions: vec![condition(
            ObservedRuntimeConditionKind::Quarantined,
            &digest,
        )],
    })
}

fn manifest_artifacts(
    manifest: &InstalledRuntimeManifest,
    physically_ready: bool,
) -> Result<Vec<ObservedArtifactClassification>> {
    let mut artifacts = vec![ObservedArtifactClassification::RetainedAuthorityOrData {
        artifact_id: artifact_id(
            "installed-runtime-manifest",
            manifest.cat_id.as_str().as_bytes(),
        )?,
        evidence_digest: manifest.manifest_digest.clone(),
    }];
    if physically_ready {
        for (label, digest) in [
            ("runtime-config", &manifest.runtime_config_digest),
            ("execution-receipt", &manifest.execution_receipt_digest),
            ("guest-ready-receipt", &manifest.guest_ready_receipt_digest),
        ] {
            artifacts.push(ObservedArtifactClassification::AdoptableCatState {
                artifact_id: artifact_id(label, manifest.cat_id.as_str().as_bytes())?,
                ownership_digest: digest.clone(),
            });
        }
        for volume in &manifest.volumes {
            if let Some(digest) = &volume.authority_receipt_digest {
                artifacts.push(ObservedArtifactClassification::AdoptableCatState {
                    artifact_id: artifact_id(
                        "volume-authority-receipt",
                        volume.volume_id.as_str().as_bytes(),
                    )?,
                    ownership_digest: digest.clone(),
                });
            }
        }
    }
    sort_artifacts(&mut artifacts);
    Ok(artifacts)
}

fn authority_observations(
    inputs: &PhysicalInputs,
    manifest: &InstalledRuntimeManifest,
) -> Vec<ObservedVolumeWatermarkSummary> {
    let mut observations = manifest
        .volumes
        .iter()
        .filter_map(|volume| {
            inputs.authority.get(&volume.volume_id).map(|authority| {
                unknown_watermark_observation(
                    &volume.volume_id,
                    &volume.disk_id,
                    volume.disk_role,
                    authority,
                )
            })
        })
        .collect::<Vec<_>>();
    observations.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    observations
}

fn progress_authority_observations(
    inputs: &PhysicalInputs,
    manifest: &InstalledRuntimeProgressManifest,
) -> Vec<ObservedVolumeWatermarkSummary> {
    let mut observations = manifest
        .volumes
        .iter()
        .filter_map(|volume| {
            inputs.authority.get(&volume.volume_id).map(|authority| {
                unknown_watermark_observation(
                    &volume.volume_id,
                    &volume.disk_id,
                    volume.disk_role,
                    authority,
                )
            })
        })
        .collect::<Vec<_>>();
    observations.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    observations
}

fn receipt_observation(
    node_id: &Id,
    receipt: &VolumeTerminalReceipt,
) -> ObservedVolumeWatermarkSummary {
    ObservedVolumeWatermarkSummary {
        volume_id: receipt.volume_id.clone(),
        disk_id: receipt.disk_id.clone(),
        disk_role: receipt.disk_role,
        observed_attachment: ObservedVolumeAttachment::Owned {
            owner_node_id: node_id.clone(),
            attachment_id: receipt.attachment_id.clone(),
            attachment_epoch: receipt.attachment_epoch,
        },
        observed_watermark: ObservedVolumeWatermark::Known {
            local_durable_generation: receipt.local_durable_generation,
            remote_durable_generation: receipt.remote_durable_generation,
        },
    }
}

fn unknown_watermark_observation(
    volume_id: &Id,
    disk_id: &Id,
    disk_role: cats_api::runtime_lifecycle::DiskRole,
    authority: &NodeVolumeInventoryRecord,
) -> ObservedVolumeWatermarkSummary {
    let evidence = authority_evidence_digest(authority);
    let observed_attachment = match (&authority.volume.admin_state, &authority.binding) {
        (VolumeAdminState::Active, Some(binding)) => ObservedVolumeAttachment::Owned {
            owner_node_id: binding.owner_node_id.clone(),
            attachment_id: binding.attachment_id.clone(),
            attachment_epoch: binding.attachment_epoch,
        },
        (VolumeAdminState::Active, None) => ObservedVolumeAttachment::Unowned {
            attachment_epoch: authority.volume.lease_epoch,
        },
        (VolumeAdminState::Deleting { .. }, _) => ObservedVolumeAttachment::Deleting {
            previous_owner_node_id: authority
                .binding
                .as_ref()
                .map(|binding| binding.owner_node_id.clone()),
            fenced_attachment_epoch: authority.volume.lease_epoch,
        },
    };
    ObservedVolumeWatermarkSummary {
        volume_id: volume_id.clone(),
        disk_id: disk_id.clone(),
        disk_role,
        observed_attachment,
        observed_watermark: ObservedVolumeWatermark::Unknown {
            evidence_digest: evidence,
        },
    }
}

fn authority_evidence_digest(record: &NodeVolumeInventoryRecord) -> Sha256Digest {
    let value = serde_json::json!({
        "volume": record.volume,
        "binding": record.binding,
    });
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    digest_parts(PHYSICAL_JOIN_DOMAIN, &[b"authority", &canonical])
}

fn physical_join_digest(
    manifest: &InstalledRuntimeManifest,
    cgroup_digest: &Sha256Digest,
    volumes: &[VolumeTerminalReceipt],
    state: &str,
) -> Sha256Digest {
    let canonical =
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&serde_json::json!({
            "version": 1,
            "manifest_digest": manifest.manifest_digest,
            "cgroup_digest": cgroup_digest,
            "state": state,
            "volumes": volumes,
        }));
    digest_parts(PHYSICAL_JOIN_DOMAIN, &[&canonical])
}

fn progress_physical_digest(
    manifest: &InstalledRuntimeProgressManifest,
    state: ObservedRuntimePhysicalState,
) -> Sha256Digest {
    let canonical =
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&serde_json::json!({
            "version": 1,
            "manifest_digest": manifest.manifest_digest,
            "physical_state": state,
        }));
    digest_parts(PHYSICAL_JOIN_DOMAIN, &[&canonical])
}

fn condition(
    kind: ObservedRuntimeConditionKind,
    digest: &Sha256Digest,
) -> ObservedRuntimeCondition {
    ObservedRuntimeCondition {
        kind,
        evidence_digest: digest.clone(),
    }
}

fn sort_artifacts(artifacts: &mut Vec<ObservedArtifactClassification>) {
    artifacts.sort_by(|left, right| left.artifact_id().cmp(right.artifact_id()));
    artifacts.dedup_by(|left, right| left == right);
}

#[derive(Default)]
struct ExpectedCanonicalLineages {
    leaves: BTreeSet<PathBuf>,
    source_quarantines: Vec<ObservedArtifactClassification>,
}

impl ExpectedCanonicalLineages {
    fn insert(&mut self, relative: PathBuf) {
        self.leaves.insert(relative);
    }
}

fn expected_canonical_lineages(
    state: &crate::state_directory::StateDirectory,
    finals: &[InstalledRuntimeManifest],
    progress: &[InstalledRuntimeProgressManifest],
    terminal_retained: &[TerminalRetainedRuntimeManifest],
    warm: &[InstalledWarmSnapshotInventoryEntry],
) -> Result<ExpectedCanonicalLineages> {
    let mut expected = ExpectedCanonicalLineages::default();
    for manifest in finals {
        for volume in &manifest.volumes {
            insert_explicit_expected_lineage(
                &mut expected,
                state,
                &manifest.cat_id,
                &volume.volume_id,
                &volume.attachment_id,
                volume.attachment_epoch.get(),
                Path::new(volume.local_lineage_data_directory.as_str()),
                &manifest.manifest_digest,
            )?;
        }
    }
    for manifest in progress {
        for volume in &manifest.volumes {
            if let Some(path) = &volume.local_lineage_data_directory {
                insert_explicit_expected_lineage(
                    &mut expected,
                    state,
                    &manifest.cat_id,
                    &volume.volume_id,
                    &volume.attachment_id,
                    volume.attachment_epoch.get(),
                    Path::new(path.as_str()),
                    &manifest.manifest_digest,
                )?;
            }
        }
    }
    for manifest in terminal_retained {
        if let Some(progress) = &manifest.runtime_progress {
            for volume in &progress.volumes {
                if let Some(path) = &volume.local_lineage_data_directory {
                    insert_explicit_expected_lineage(
                        &mut expected,
                        state,
                        &manifest.cat_id,
                        &volume.volume_id,
                        &volume.attachment_id,
                        volume.attachment_epoch.get(),
                        Path::new(path.as_str()),
                        &manifest.manifest_digest,
                    )?;
                }
            }
        }
        if let TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } =
            &manifest.retention_mode
        {
            for volume in &evidence.volumes {
                if let Some(path) = &volume.local_lineage_data_directory {
                    insert_explicit_expected_lineage(
                        &mut expected,
                        state,
                        &manifest.cat_id,
                        &volume.retained_receipt.volume_id,
                        &volume.retained_receipt.attachment_id,
                        volume.retained_receipt.attachment_epoch.get(),
                        Path::new(path.as_str()),
                        &manifest.manifest_digest,
                    )?;
                }
            }
        }
    }
    for entry in warm {
        let (cat_id, receipts) = match entry {
            InstalledWarmSnapshotInventoryEntry::Terminal(artifact) => (
                &artifact.cat_id,
                artifact.retained_volume_receipts.as_slice(),
            ),
            InstalledWarmSnapshotInventoryEntry::RetainedPrepared(artifact) => (
                &artifact.cat_id,
                artifact.retained_volume_receipts.as_slice(),
            ),
            InstalledWarmSnapshotInventoryEntry::RetainedIntent(artifact) => (
                &artifact.cat_id,
                artifact.retained_volume_receipts.as_slice(),
            ),
            InstalledWarmSnapshotInventoryEntry::Quarantined { .. } => continue,
        };
        for receipt in receipts {
            expected.insert(canonical_lineage_relative_path(
                cat_id,
                &receipt.volume_id,
                &receipt.attachment_id,
                receipt.attachment_epoch.get(),
            ));
        }
    }
    expected
        .source_quarantines
        .sort_by(|left, right| left.artifact_id().cmp(right.artifact_id()));
    expected.source_quarantines.dedup();
    Ok(expected)
}

#[allow(clippy::too_many_arguments)]
fn insert_explicit_expected_lineage(
    expected: &mut ExpectedCanonicalLineages,
    state: &crate::state_directory::StateDirectory,
    cat_id: &Id,
    volume_id: &Id,
    attachment_id: &Id,
    attachment_epoch: u64,
    actual: &Path,
    source_digest: &Sha256Digest,
) -> Result<()> {
    let relative =
        canonical_lineage_relative_path(cat_id, volume_id, attachment_id, attachment_epoch);
    let canonical = state.path().join(&relative);
    if actual != canonical {
        let mut evidence = Vec::new();
        append_evidence(&mut evidence, b"noncanonical-manifest-lineage");
        append_evidence(&mut evidence, source_digest.as_bytes());
        append_evidence(&mut evidence, actual.as_os_str().as_bytes());
        append_evidence(&mut evidence, canonical.as_os_str().as_bytes());
        expected.source_quarantines.push(quarantined_artifact(
            "noncanonical-lineage-manifest",
            &evidence,
        )?);
        return Ok(());
    }
    expected.insert(relative);
    Ok(())
}

fn canonical_lineage_relative_path(
    cat_id: &Id,
    volume_id: &Id,
    attachment_id: &Id,
    attachment_epoch: u64,
) -> PathBuf {
    PathBuf::from(LINEAGE_NAMESPACE)
        .join(format!("cat-{cat_id}"))
        .join(format!("volume-{volume_id}"))
        .join(format!("attachment-{attachment_id}"))
        .join(format!("epoch-{attachment_epoch}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LineageDirectoryIdentity {
    device: u64,
    inode: u64,
}

struct CanonicalLineageScan<'a> {
    expected: &'a ExpectedCanonicalLineages,
    deadline: Instant,
    entry_limit: usize,
    entry_count: usize,
    seen_directories: BTreeMap<LineageDirectoryIdentity, PathBuf>,
    accounted_expected: BTreeSet<PathBuf>,
    unattributed: &'a mut Vec<ObservedArtifactClassification>,
}

fn classify_canonical_lineage_namespace(
    state_root: &File,
    expected: &ExpectedCanonicalLineages,
    deadline: Instant,
    entry_limit: usize,
    unattributed: &mut Vec<ObservedArtifactClassification>,
) -> Result<()> {
    anyhow::ensure!(entry_limit > 0, "canonical lineage entry bound is zero");
    let mut scan = CanonicalLineageScan {
        expected,
        deadline,
        entry_limit,
        entry_count: 0,
        seen_directories: BTreeMap::new(),
        accounted_expected: BTreeSet::new(),
        unattributed,
    };
    let data_name = CString::new(LINEAGE_NAMESPACE).expect("fixed namespace has no NUL");
    let data_relative = PathBuf::from(LINEAGE_NAMESPACE);
    let Some(before) = fstatat_lineage_nofollow(state_root, &data_name)? else {
        scan.quarantine_missing_expected()?;
        return Ok(());
    };
    scan.consume_entry("canonical lineage namespace")?;
    if before.st_mode & libc::S_IFMT != libc::S_IFDIR {
        scan.quarantine_stat(
            lineage_stat_conflict_reason(&before),
            &data_relative,
            &before,
            None,
        )?;
        scan.account_expected_under(&data_relative);
        scan.quarantine_missing_expected()?;
        return Ok(());
    }
    let (data, identity) = open_exact_lineage_directory(state_root, &data_name, &before)
        .context("open canonical local-lineage namespace")?;
    scan.seen_directories
        .insert(identity, data_relative.clone());
    scan.scan_directory(&data, &data_relative, 0)?;
    revalidate_lineage_directory_entry(state_root, &data_name, identity)
        .context("canonical local-lineage namespace changed during scan")?;
    scan.quarantine_missing_expected()?;
    Ok(())
}

impl CanonicalLineageScan<'_> {
    fn scan_directory(&mut self, directory: &File, relative: &Path, depth: usize) -> Result<bool> {
        anyhow::ensure!(
            depth < LINEAGE_DEPTH,
            "canonical lineage scan exceeded its depth"
        );
        let mut names = lineage_directory_entry_names(directory)
            .context("enumerate canonical local-lineage directory")?;
        names.retain(|name| name.as_slice() != b"." && name.as_slice() != b"..");
        names.sort();
        let mut observed = false;
        for name in names {
            self.consume_entry("canonical lineage tree")?;
            let component =
                CString::new(name.clone()).context("canonical lineage entry contains NUL")?;
            let child_relative = relative.join(OsString::from_vec(name.clone()));
            let Some(before) = fstatat_lineage_nofollow(directory, &component)? else {
                anyhow::bail!("canonical lineage entry disappeared during descriptor scan")
            };
            if !is_canonical_lineage_component(depth, &name) {
                self.quarantine_stat("noncanonical-component", &child_relative, &before, None)?;
                observed = true;
                continue;
            }
            if before.st_mode & libc::S_IFMT != libc::S_IFDIR {
                self.quarantine_stat(
                    lineage_stat_conflict_reason(&before),
                    &child_relative,
                    &before,
                    None,
                )?;
                self.account_expected_under(&child_relative);
                observed = true;
                continue;
            }
            let (child, identity) = open_exact_lineage_directory(directory, &component, &before)
                .with_context(|| {
                    format!(
                        "open canonical lineage component {}",
                        child_relative.display()
                    )
                })?;
            if let Some(first) = self
                .seen_directories
                .insert(identity, child_relative.clone())
            {
                self.quarantine_stat("directory-alias", &child_relative, &before, Some(&first))?;
                self.account_expected_under(&child_relative);
                observed = true;
                continue;
            }
            let child_observed = if depth + 1 == LINEAGE_DEPTH {
                if self.expected.leaves.contains(&child_relative) {
                    self.accounted_expected.insert(child_relative.clone());
                } else {
                    self.quarantine_stat(
                        "unexpected-canonical-lineage",
                        &child_relative,
                        &before,
                        None,
                    )?;
                }
                true
            } else {
                let nested = self.scan_directory(&child, &child_relative, depth + 1)?;
                if !nested {
                    self.quarantine_stat(
                        "empty-canonical-lineage-prefix",
                        &child_relative,
                        &before,
                        None,
                    )?;
                }
                true
            };
            revalidate_lineage_directory_entry(directory, &component, identity).with_context(
                || {
                    format!(
                        "lineage ancestor {} changed during scan",
                        child_relative.display()
                    )
                },
            )?;
            observed |= child_observed;
        }
        Ok(observed)
    }

    fn consume_entry(&mut self, label: &str) -> Result<()> {
        self.entry_count = self
            .entry_count
            .checked_add(1)
            .context("canonical lineage entry counter overflow")?;
        anyhow::ensure!(
            self.entry_count <= self.entry_limit,
            "{label} exceeds the closed entry bound"
        );
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "startup inventory deadline elapsed"
        );
        Ok(())
    }

    fn account_expected_under(&mut self, prefix: &Path) {
        self.accounted_expected.extend(
            self.expected
                .leaves
                .iter()
                .filter(|path| path.starts_with(prefix))
                .cloned(),
        );
    }

    fn quarantine_missing_expected(&mut self) -> Result<()> {
        let missing = self
            .expected
            .leaves
            .difference(&self.accounted_expected)
            .cloned()
            .collect::<Vec<_>>();
        for relative in missing {
            self.quarantine("missing-expected-lineage", &relative, None, None)?;
        }
        Ok(())
    }

    fn quarantine_stat(
        &mut self,
        reason: &str,
        relative: &Path,
        stat: &libc::stat,
        alias: Option<&Path>,
    ) -> Result<()> {
        let stat_evidence = format!(
            "device={};inode={};mode={};links={}",
            stat.st_dev, stat.st_ino, stat.st_mode, stat.st_nlink
        );
        self.quarantine(reason, relative, Some(stat_evidence.as_bytes()), alias)
    }

    fn quarantine(
        &mut self,
        reason: &str,
        relative: &Path,
        stat_evidence: Option<&[u8]>,
        alias: Option<&Path>,
    ) -> Result<()> {
        let mut evidence = Vec::new();
        append_evidence(&mut evidence, reason.as_bytes());
        append_evidence(&mut evidence, relative.as_os_str().as_bytes());
        if let Some(stat_evidence) = stat_evidence {
            append_evidence(&mut evidence, stat_evidence);
        }
        if let Some(alias) = alias {
            append_evidence(&mut evidence, alias.as_os_str().as_bytes());
        }
        self.unattributed.push(quarantined_artifact(
            "canonical-lineage-residue",
            &evidence,
        )?);
        Ok(())
    }
}

fn is_canonical_lineage_component(depth: usize, name: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    if depth == LINEAGE_DEPTH - 1 {
        let Some(epoch) = name.strip_prefix("epoch-") else {
            return false;
        };
        return epoch
            .parse::<u64>()
            .is_ok_and(|parsed| format!("epoch-{parsed}") == name);
    }
    let prefix = match depth {
        0 => "cat-",
        1 => "volume-",
        2 => "attachment-",
        _ => return false,
    };
    let Some(value) = name.strip_prefix(prefix) else {
        return false;
    };
    Id::new(value.to_owned()).is_some_and(|parsed| format!("{prefix}{}", parsed.as_str()) == name)
}

fn lineage_stat_conflict_reason(stat: &libc::stat) -> &'static str {
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFLNK => "symbolic-link",
        libc::S_IFDIR => "directory-conflict",
        _ if stat.st_nlink > 1 => "hard-linked-nondirectory",
        _ => "nondirectory",
    }
}

fn open_exact_lineage_directory(
    parent: &File,
    name: &CStr,
    before: &libc::stat,
) -> Result<(File, LineageDirectoryIdentity)> {
    let file = loop {
        // SAFETY: parent and name stay live; successful openat returns one
        // fresh descriptor adopted exactly once below.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0,
            )
        };
        if descriptor >= 0 {
            // SAFETY: successful openat returned a uniquely owned descriptor.
            break unsafe { File::from_raw_fd(descriptor) };
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error).context("open no-follow lineage directory");
        }
    };
    let metadata = file
        .metadata()
        .context("inspect opened lineage directory")?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "opened lineage is not a directory"
    );
    let identity = LineageDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    anyhow::ensure!(
        identity == lineage_stat_identity(before)?,
        "lineage entry changed identity while opening"
    );
    let Some(after) = fstatat_lineage_nofollow(parent, name)? else {
        anyhow::bail!("lineage entry disappeared while opening")
    };
    anyhow::ensure!(
        after.st_mode & libc::S_IFMT == libc::S_IFDIR && lineage_stat_identity(&after)? == identity,
        "lineage entry changed identity while opening"
    );
    Ok((file, identity))
}

fn revalidate_lineage_directory_entry(
    parent: &File,
    name: &CStr,
    expected: LineageDirectoryIdentity,
) -> Result<()> {
    let Some(current) = fstatat_lineage_nofollow(parent, name)? else {
        anyhow::bail!("lineage directory disappeared during scan")
    };
    anyhow::ensure!(
        current.st_mode & libc::S_IFMT == libc::S_IFDIR
            && lineage_stat_identity(&current)? == expected,
        "lineage directory changed identity during scan"
    );
    Ok(())
}

fn lineage_stat_identity(stat: &libc::stat) -> Result<LineageDirectoryIdentity> {
    Ok(LineageDirectoryIdentity {
        device: lineage_device_number(stat.st_dev)?,
        inode: stat.st_ino,
    })
}

#[cfg(target_os = "linux")]
fn lineage_device_number(device: libc::dev_t) -> Result<u64> {
    Ok(device)
}

#[cfg(not(target_os = "linux"))]
fn lineage_device_number(device: libc::dev_t) -> Result<u64> {
    u64::try_from(device).context("lineage device is negative")
}

fn fstatat_lineage_nofollow(directory: &File, name: &CStr) -> Result<Option<libc::stat>> {
    loop {
        // SAFETY: descriptor/name remain live, stat points to writable storage,
        // and AT_SYMLINK_NOFOLLOW prevents path redirection.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: all pointers and the directory descriptor are valid for the call.
        let result = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                std::ptr::addr_of_mut!(stat),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(Some(stat));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).context("fstatat no-follow lineage entry");
    }
}

fn lineage_directory_entry_names(directory: &File) -> Result<Vec<Vec<u8>>> {
    let duplicate = directory
        .try_clone()
        .context("duplicate canonical lineage directory descriptor")?
        .into_raw_fd();
    // SAFETY: fdopendir takes ownership on success; DirectoryStream closes it.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: failed fdopendir did not consume the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(error).context("open canonical lineage directory stream");
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
        clear_lineage_errno();
        // SAFETY: the DIR remains exclusively owned and live for this call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error).context("read canonical lineage directory entry");
            }
            break;
        }
        // SAFETY: d_name is NUL terminated and copied before the next readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        names.push(name.to_bytes().to_vec());
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn clear_lineage_errno() {
    // SAFETY: this is the current thread's errno slot and is cleared only for
    // the immediately following readdir EOF/error distinction.
    unsafe { *libc::__errno_location() = 0 }
}

#[cfg(target_os = "macos")]
fn clear_lineage_errno() {
    // SAFETY: this is the current thread's errno slot and is cleared only for
    // the immediately following readdir EOF/error distinction.
    unsafe { *libc::__error() = 0 }
}

fn revalidate_state_scan_root(
    state: &crate::state_directory::StateDirectory,
    retained: &File,
) -> Result<()> {
    let reopened = state
        .try_reopen_directory()
        .context("reopen identity-selected StateDirectory after complete scan")?;
    let retained = retained
        .metadata()
        .context("inspect retained complete-scan StateDirectory")?;
    let reopened = reopened
        .metadata()
        .context("inspect reopened complete-scan StateDirectory")?;
    anyhow::ensure!(
        retained.file_type().is_dir()
            && reopened.file_type().is_dir()
            && retained.dev() == reopened.dev()
            && retained.ino() == reopened.ino(),
        "StateDirectory changed identity during complete physical inventory"
    );
    Ok(())
}

struct ExpectedGlobalPhysicalArtifacts {
    cat_slices: BTreeMap<Vec<u8>, Id>,
    kernel_nbd: BTreeMap<PathBuf, (Id, u32)>,
    sockets: BTreeSet<PathBuf>,
}

fn classify_global_physical_residue(
    config: &InstalledPhysicalInspectionConfig,
    finals: &BTreeMap<Id, InstalledRuntimeManifest>,
    progress: &BTreeMap<Id, Vec<InstalledRuntimeProgressManifest>>,
    deadline: Instant,
    unattributed: &mut Vec<ObservedArtifactClassification>,
) -> Result<()> {
    let expected = expected_global_physical_artifacts(finals, progress)?;
    classify_unattributed_cat_slices(config, &expected, deadline, unattributed)?;
    classify_unattributed_managed_processes(config, &expected, deadline, unattributed)?;
    classify_unattributed_kernel_nbd(config, &expected, deadline, unattributed)?;
    classify_unattributed_managed_sockets(
        &config.managed_socket_roots,
        &expected,
        deadline,
        unattributed,
    )?;
    Ok(())
}

fn expected_global_physical_artifacts(
    finals: &BTreeMap<Id, InstalledRuntimeManifest>,
    progress: &BTreeMap<Id, Vec<InstalledRuntimeProgressManifest>>,
) -> Result<ExpectedGlobalPhysicalArtifacts> {
    let mut expected = ExpectedGlobalPhysicalArtifacts {
        cat_slices: BTreeMap::new(),
        kernel_nbd: BTreeMap::new(),
        sockets: BTreeSet::new(),
    };
    for (cat_id, manifest) in finals {
        insert_expected_cat_slice(&mut expected, cat_id)?;
        insert_expected_vmm_sockets(&mut expected.sockets, &manifest.vmm);
        for volume in &manifest.volumes {
            expected
                .sockets
                .insert(PathBuf::from(volume.blockd_control_socket_path.as_str()));
            insert_expected_frontend(&mut expected, cat_id, &volume.frontend)?;
        }
    }
    for (cat_id, manifests) in progress {
        insert_expected_cat_slice(&mut expected, cat_id)?;
        for manifest in manifests {
            if let Some(vmm) = &manifest.vmm {
                insert_expected_vmm_sockets(&mut expected.sockets, vmm);
            }
            for volume in &manifest.volumes {
                if let Some(path) = &volume.blockd_control_socket_path {
                    expected.sockets.insert(PathBuf::from(path.as_str()));
                }
                if let Some(frontend) = &volume.frontend {
                    insert_expected_frontend(&mut expected, cat_id, frontend)?;
                }
            }
        }
    }
    Ok(expected)
}

fn insert_expected_cat_slice(
    expected: &mut ExpectedGlobalPhysicalArtifacts,
    cat_id: &Id,
) -> Result<()> {
    let slice = cat_execution_slice_id(cat_id);
    if let Some(previous) = expected
        .cat_slices
        .insert(slice.as_str().as_bytes().to_vec(), cat_id.clone())
    {
        anyhow::ensure!(
            previous == *cat_id,
            "two Cats derive one deterministic execution slice"
        );
    }
    Ok(())
}

fn insert_expected_vmm_sockets(sockets: &mut BTreeSet<PathBuf>, vmm: &InstalledRuntimeVmmManifest) {
    sockets.insert(PathBuf::from(vmm.api_socket_path.as_str()));
    sockets.insert(PathBuf::from(vmm.vsock_socket_path.as_str()));
}

fn insert_expected_frontend(
    expected: &mut ExpectedGlobalPhysicalArtifacts,
    cat_id: &Id,
    frontend: &InstalledRuntimeBlockFrontend,
) -> Result<()> {
    match frontend {
        InstalledRuntimeBlockFrontend::KernelNbd {
            device_path,
            client,
        } => {
            let path = PathBuf::from(device_path.as_str());
            let identity = (cat_id.clone(), client.pid);
            if let Some(previous) = expected.kernel_nbd.insert(path, identity.clone()) {
                anyhow::ensure!(
                    previous == identity,
                    "installed manifests assign one kernel-NBD device more than once"
                );
            }
        }
        InstalledRuntimeBlockFrontend::VhostUserBlk { socket_path } => {
            expected.sockets.insert(PathBuf::from(socket_path.as_str()));
        }
    }
    Ok(())
}

fn classify_unattributed_cat_slices(
    config: &InstalledPhysicalInspectionConfig,
    expected: &ExpectedGlobalPhysicalArtifacts,
    deadline: Instant,
    unattributed: &mut Vec<ObservedArtifactClassification>,
) -> Result<()> {
    let entries = fs::read_dir(&config.cgroup_root).context("enumerate Host cgroup root")?;
    let mut count = 0_usize;
    for entry in entries {
        ensure_scan_budget(deadline, &mut count, "Host cgroup root")?;
        let entry = entry.context("read Host cgroup root entry")?;
        let name = entry.file_name();
        let bytes = name.as_bytes();
        let reserved_namespace = bytes.starts_with(b"cats-cat-") && bytes.ends_with(b".slice");
        if !reserved_namespace {
            continue;
        }
        let canonical = std::str::from_utf8(bytes)
            .ok()
            .is_some_and(is_cat_execution_slice_name);
        if !canonical || !expected.cat_slices.contains_key(bytes) {
            unattributed.push(quarantined_artifact("unattributed-cat-cgroup", bytes)?);
        }
    }
    Ok(())
}

fn classify_unattributed_managed_processes(
    config: &InstalledPhysicalInspectionConfig,
    expected: &ExpectedGlobalPhysicalArtifacts,
    deadline: Instant,
    unattributed: &mut Vec<ObservedArtifactClassification>,
) -> Result<()> {
    let entries = fs::read_dir(&config.proc_root).context("enumerate Host process inventory")?;
    let managed = configured_managed_binaries(config);
    let known_cgroups = expected
        .cat_slices
        .keys()
        .map(|slice| format!("/{}", String::from_utf8_lossy(slice)))
        .collect::<Vec<_>>();
    let mut count = 0_usize;
    for entry in entries {
        ensure_scan_budget(deadline, &mut count, "Host process inventory")?;
        let entry = entry.context("read Host process inventory entry")?;
        let Some(pid) = parse_process_directory(entry.file_name().as_bytes()) else {
            continue;
        };
        let process = config.proc_root.join(pid.to_string());
        let executable_before = match fs::read_link(process.join("exe")) {
            Ok(path) => path,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("read managed process executable"),
        };
        let Some((configured_binary, deleted)) =
            match_managed_executable(&executable_before, &managed)
        else {
            continue;
        };
        let stat_before = match fs::read_to_string(process.join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("read managed process identity"),
        };
        anyhow::ensure!(
            stat_before.len() <= 64 * 1024,
            "managed process stat exceeds the closed byte bound"
        );
        let start_ticks = crate::proc::parse_start_ticks(&stat_before)
            .context("managed process stat is malformed")?;
        let cgroup = match read_unified_process_cgroup(&config.proc_root, pid) {
            Ok(cgroup) => cgroup,
            Err(error) if error_chain_is_not_found(&error) => continue,
            Err(error) => return Err(error).context("read managed process cgroup"),
        };
        let executable_after = match fs::read_link(process.join("exe")) {
            Ok(path) => path,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("re-read managed process executable"),
        };
        let stat_after = match fs::read_to_string(process.join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("re-read managed process identity"),
        };
        anyhow::ensure!(
            executable_after == executable_before
                && crate::proc::parse_start_ticks(&stat_after) == Some(start_ticks),
            "managed process identity changed during complete inventory"
        );
        let attributed = known_cgroups
            .iter()
            .any(|known| cgroup == *known || cgroup.starts_with(&(known.clone() + "/")));
        if deleted || !attributed {
            let mut evidence = Vec::new();
            append_evidence(&mut evidence, &pid.to_be_bytes());
            append_evidence(&mut evidence, &start_ticks.to_be_bytes());
            append_evidence(
                &mut evidence,
                configured_binary.as_os_str().as_encoded_bytes(),
            );
            append_evidence(&mut evidence, cgroup.as_bytes());
            append_evidence(&mut evidence, if deleted { b"deleted" } else { b"live" });
            unattributed.push(quarantined_artifact(
                "unattributed-managed-process",
                &evidence,
            )?);
        }
    }
    Ok(())
}

fn classify_unattributed_kernel_nbd(
    config: &InstalledPhysicalInspectionConfig,
    expected: &ExpectedGlobalPhysicalArtifacts,
    deadline: Instant,
    unattributed: &mut Vec<ObservedArtifactClassification>,
) -> Result<()> {
    let Some(kernel) = &config.kernel_nbd else {
        return Ok(());
    };
    let slots = scan_kernel_nbd_pool(kernel, &config.proc_root)
        .context("scan complete kernel-NBD pool for unattributed residue")?;
    for slot in slots {
        anyhow::ensure!(
            Instant::now() < deadline,
            "startup inventory deadline elapsed"
        );
        let (label, process_id) = match &slot {
            KernelNbdSlot::Free { .. } => continue,
            KernelNbdSlot::Serving { process_id, .. } => {
                let exact = expected.kernel_nbd.get(slot.device_path());
                let cgroup = read_unified_process_cgroup(&config.proc_root, *process_id)
                    .context("read live kernel-NBD client cgroup")?;
                let attributed = exact.is_some_and(|(cat_id, expected_pid)| {
                    let prefix = format!("/{}", cat_execution_slice_id(cat_id));
                    *expected_pid == *process_id
                        && (cgroup == prefix || cgroup.starts_with(&(prefix + "/")))
                });
                if attributed {
                    continue;
                }
                ("unattributed-kernel-nbd", Some(*process_id))
            }
            KernelNbdSlot::Leaked { .. } => ("leaked-kernel-nbd", None),
        };
        let mut evidence = Vec::new();
        append_evidence(
            &mut evidence,
            slot.device_path().as_os_str().as_encoded_bytes(),
        );
        if let Some(pid) = process_id {
            append_evidence(&mut evidence, &pid.to_be_bytes());
        }
        unattributed.push(quarantined_artifact(label, &evidence)?);
    }
    Ok(())
}

fn classify_unattributed_managed_sockets(
    managed_socket_roots: &[PathBuf],
    expected: &ExpectedGlobalPhysicalArtifacts,
    deadline: Instant,
    unattributed: &mut Vec<ObservedArtifactClassification>,
) -> Result<()> {
    let mut roots = managed_socket_roots.to_vec();
    roots.sort();
    roots.dedup();
    let mut disjoint_roots: Vec<PathBuf> = Vec::with_capacity(roots.len());
    for root in roots {
        if !disjoint_roots
            .iter()
            .any(|ancestor| root.starts_with(ancestor))
        {
            disjoint_roots.push(root);
        }
    }
    let mut count = 0_usize;
    for root in disjoint_roots {
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect managed socket root"),
        };
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "managed socket root is not one nofollow directory"
        );
        let mut directories = vec![(root.clone(), 0_usize)];
        let mut cursor = 0_usize;
        while cursor < directories.len() {
            let (directory, depth) = directories[cursor].clone();
            cursor += 1;
            anyhow::ensure!(
                depth <= MANAGED_SOCKET_TREE_DEPTH_LIMIT,
                "managed socket tree exceeds its closed depth bound"
            );
            let entries = fs::read_dir(&directory).context("enumerate managed socket tree")?;
            for entry in entries {
                ensure_scan_budget(deadline, &mut count, "managed socket tree")?;
                let entry = entry.context("read managed socket tree entry")?;
                let path = entry.path();
                let metadata =
                    fs::symlink_metadata(&path).context("inspect managed socket tree entry")?;
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    directories.push((path, depth + 1));
                    continue;
                }
                let exact_expected = expected.sockets.contains(&path)
                    && metadata.file_type().is_socket()
                    && !metadata.file_type().is_symlink();
                if exact_expected {
                    continue;
                }
                let relative = path
                    .strip_prefix(&root)
                    .context("managed socket artifact escaped its root")?;
                let mut evidence = Vec::new();
                append_evidence(&mut evidence, root.as_os_str().as_encoded_bytes());
                append_evidence(&mut evidence, relative.as_os_str().as_encoded_bytes());
                append_evidence(&mut evidence, &metadata.dev().to_be_bytes());
                append_evidence(&mut evidence, &metadata.ino().to_be_bytes());
                append_evidence(&mut evidence, &metadata.mode().to_be_bytes());
                unattributed.push(quarantined_artifact(
                    "unattributed-managed-socket",
                    &evidence,
                )?);
            }
        }
    }
    Ok(())
}

fn configured_managed_binaries(config: &InstalledPhysicalInspectionConfig) -> BTreeSet<PathBuf> {
    let mut managed = config.managed_process_binaries.clone();
    if let Some(kernel) = &config.kernel_nbd {
        managed.insert(kernel.nbd_client_binary.clone());
    }
    managed
}

fn parse_process_directory(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes)
        .ok()?
        .parse()
        .ok()
        .filter(|pid| *pid > 0)
}

fn match_managed_executable(
    observed: &Path,
    managed: &BTreeSet<PathBuf>,
) -> Option<(PathBuf, bool)> {
    if managed.contains(observed) {
        return Some((observed.to_path_buf(), false));
    }
    let bytes = observed.as_os_str().as_bytes();
    let base = bytes.strip_suffix(DELETED_EXECUTABLE_SUFFIX)?;
    let base = PathBuf::from(OsString::from_vec(base.to_vec()));
    managed.contains(&base).then_some((base, true))
}

fn error_chain_is_not_found(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|source| source.downcast_ref::<std::io::Error>())
        .any(|error| error.kind() == ErrorKind::NotFound)
}

fn ensure_scan_budget(deadline: Instant, count: &mut usize, label: &str) -> Result<()> {
    *count = count
        .checked_add(1)
        .context("complete physical inventory entry counter overflow")?;
    anyhow::ensure!(
        *count <= GLOBAL_PHYSICAL_ENTRY_LIMIT,
        "{label} exceeds the closed entry bound"
    );
    anyhow::ensure!(
        Instant::now() < deadline,
        "startup inventory deadline elapsed"
    );
    Ok(())
}

fn append_evidence(target: &mut Vec<u8>, part: &[u8]) {
    target.extend_from_slice(&(part.len() as u64).to_be_bytes());
    target.extend_from_slice(part);
}

fn quarantine_retired_checkpoint_namespace(
    directory: &Path,
    deadline: Instant,
    unattributed: &mut Vec<ObservedArtifactClassification>,
) -> Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("enumerate retired reconciliation namespace"),
    };
    for entry in entries {
        anyhow::ensure!(
            Instant::now() < deadline,
            "startup inventory deadline elapsed"
        );
        let entry = entry.context("read retired reconciliation entry")?;
        let name = entry.file_name();
        unattributed.push(quarantined_artifact(
            "retired-runtime-checkpoint",
            name.as_encoded_bytes(),
        )?);
    }
    Ok(())
}

fn current_unix_millis() -> Result<UnixMillis> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Host wall clock precedes Unix epoch")?;
    let millis = u64::try_from(duration.as_millis()).context("Host wall clock overflows u64")?;
    UnixMillis::new(millis).context("Host wall clock is not a valid UnixMillis")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    use cats_api::runtime_lifecycle::{
        DiskRole, ImmutableRuntimeConfig, LifecycleCommand, LifecyclePredecessor,
        RuntimeNetworkConfig, RuntimeVolumeAuthorityInput, RuntimeVolumeConfig,
        RuntimeVolumeGuestBinding, StartSource, StartSpec, StartVolumeAuthority,
    };
    use cats_api::runtime_reconciliation::{
        Durability, Epoch, FenceEpoch, Ipv4Address, MacAddress,
    };

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid fixture ID")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn random(byte: u8) -> RandomId128 {
        RandomId128::new(format!("{byte:02x}").repeat(16)).expect("valid random fixture ID")
    }

    fn expected_lineage(
        cat: &str,
        volume: &str,
        attachment: &str,
        epoch: u64,
    ) -> (ExpectedCanonicalLineages, PathBuf) {
        let relative =
            canonical_lineage_relative_path(&id(cat), &id(volume), &id(attachment), epoch);
        let mut expected = ExpectedCanonicalLineages::default();
        expected.insert(relative.clone());
        (expected, relative)
    }

    fn scan_lineage_fixture(
        state: &crate::state_directory::StateDirectory,
        expected: &ExpectedCanonicalLineages,
        entry_limit: usize,
    ) -> Result<Vec<ObservedArtifactClassification>> {
        let root = state
            .try_clone_directory()
            .context("retain lineage fixture StateDirectory")?;
        let mut residue = Vec::new();
        classify_canonical_lineage_namespace(
            &root,
            expected,
            Instant::now() + Duration::from_secs(5),
            entry_limit,
            &mut residue,
        )?;
        revalidate_state_scan_root(state, &root)?;
        Ok(residue)
    }

    #[test]
    fn canonical_lineage_scan_calibrates_expected_leaf() {
        let temporary = tempfile::tempdir().expect("create canonical-lineage fixture");
        let state =
            crate::state_directory::StateDirectory::unanchored(temporary.path().to_path_buf());
        let (expected, relative) =
            expected_lineage("cat_expected", "volume_expected", "attachment_expected", 7);
        fs::create_dir_all(state.path().join(relative)).expect("create expected lineage leaf");

        assert!(scan_lineage_fixture(&state, &expected, 32)
            .expect("scan expected canonical lineage")
            .is_empty());
    }

    #[test]
    fn canonical_lineage_scan_quarantines_unknown_sibling_without_losing_expected_leaf() {
        let temporary = tempfile::tempdir().expect("create sibling-lineage fixture");
        let state =
            crate::state_directory::StateDirectory::unanchored(temporary.path().to_path_buf());
        let (expected, expected_relative) =
            expected_lineage("cat_expected", "volume_expected", "attachment_expected", 7);
        let sibling = canonical_lineage_relative_path(
            &id("cat_sibling"),
            &id("volume_sibling"),
            &id("attachment_sibling"),
            9,
        );
        fs::create_dir_all(state.path().join(expected_relative))
            .expect("create expected lineage leaf");
        fs::create_dir_all(state.path().join(sibling)).expect("create unknown sibling lineage");

        let residue =
            scan_lineage_fixture(&state, &expected, 64).expect("scan sibling lineage fixture");
        assert_eq!(residue.len(), 1);
        assert!(residue[0]
            .artifact_id()
            .as_str()
            .starts_with("canonical-lineage-residue-"));
    }

    #[test]
    fn canonical_lineage_scan_quarantines_symlinked_ancestor_without_following_it() {
        let temporary = tempfile::tempdir().expect("create symlink-lineage fixture");
        let state =
            crate::state_directory::StateDirectory::unanchored(temporary.path().to_path_buf());
        let (expected, relative) =
            expected_lineage("cat_expected", "volume_expected", "attachment_expected", 7);
        let components = relative.components().collect::<Vec<_>>();
        let cat = PathBuf::from(components[0].as_os_str()).join(components[1].as_os_str());
        let volume = state.path().join(&cat).join(components[2].as_os_str());
        fs::create_dir_all(state.path().join(&cat)).expect("create canonical Cat ancestor");
        let outside = temporary.path().join("outside-lineage");
        fs::create_dir_all(
            outside
                .join(components[3].as_os_str())
                .join(components[4].as_os_str()),
        )
        .expect("create symlink target tree");
        symlink(&outside, &volume).expect("install symlinked Volume ancestor");

        let residue =
            scan_lineage_fixture(&state, &expected, 32).expect("scan symlinked lineage ancestor");
        assert_eq!(residue.len(), 1);
    }

    #[test]
    fn canonical_lineage_scan_quarantines_type_mismatch_and_hard_link() {
        for hard_linked in [false, true] {
            let temporary = tempfile::tempdir().expect("create type-lineage fixture");
            let state =
                crate::state_directory::StateDirectory::unanchored(temporary.path().to_path_buf());
            let (expected, relative) =
                expected_lineage("cat_expected", "volume_expected", "attachment_expected", 7);
            let leaf = state.path().join(&relative);
            fs::create_dir_all(leaf.parent().expect("lineage leaf has parent"))
                .expect("create lineage ancestors");
            fs::write(&leaf, b"not a lineage directory").expect("write type mismatch");
            if hard_linked {
                fs::hard_link(&leaf, state.path().join("lineage-hard-link-alias"))
                    .expect("hard-link type mismatch");
            }

            let residue =
                scan_lineage_fixture(&state, &expected, 32).expect("scan lineage type mismatch");
            assert_eq!(residue.len(), 1);
        }
    }

    #[test]
    fn canonical_lineage_scan_fails_closed_when_bound_is_exceeded() {
        let temporary = tempfile::tempdir().expect("create bounded-lineage fixture");
        let state =
            crate::state_directory::StateDirectory::unanchored(temporary.path().to_path_buf());
        fs::create_dir_all(state.path().join(LINEAGE_NAMESPACE))
            .expect("create canonical lineage namespace");
        fs::write(state.path().join(LINEAGE_NAMESPACE).join("foreign-a"), b"a")
            .expect("write first foreign lineage entry");
        fs::write(state.path().join(LINEAGE_NAMESPACE).join("foreign-b"), b"b")
            .expect("write second foreign lineage entry");

        let error = scan_lineage_fixture(&state, &ExpectedCanonicalLineages::default(), 2)
            .expect_err("closed lineage bound must reject a larger namespace");
        assert!(error.to_string().contains("closed entry bound"));
    }

    #[test]
    fn complete_scan_rejects_state_directory_ancestor_replacement() {
        let temporary = tempfile::tempdir().expect("create StateDirectory ABA fixture");
        let lexical_parent = temporary.path().join("lexical-parent");
        let state_path = lexical_parent.join("state");
        fs::create_dir_all(&state_path).expect("create original StateDirectory");
        let source = File::open(&state_path).expect("open original StateDirectory");
        let state =
            crate::state_directory::StateDirectory::from_test_directory(&source, &state_path)
                .expect("anchor original StateDirectory");
        let retained = state
            .try_clone_directory()
            .expect("retain original StateDirectory for scan");
        let displaced = temporary.path().join("displaced-parent");
        fs::rename(&lexical_parent, &displaced).expect("displace StateDirectory ancestor");
        fs::create_dir_all(&state_path).expect("create replacement StateDirectory");

        assert!(revalidate_state_scan_root(&state, &retained).is_err());
    }

    fn restart_source_command() -> LifecycleCommandEnvelope {
        let placement = cats_api::runtime_lifecycle::PlacementIdentity {
            node_id: id("node_restart_absence"),
            placement_epoch: Epoch::new(1).expect("positive placement epoch"),
        };
        let runtime_config = ImmutableRuntimeConfig::new(
            id("config_restart_absence"),
            digest(1),
            2,
            512 * 1024 * 1024,
            digest(2),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("network_restart_absence"),
                guest_mac: MacAddress::new("02:00:00:00:00:41").expect("valid fixture MAC"),
                guest_ipv4: Ipv4Address::new("10.0.0.2").expect("valid fixture guest IP"),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").expect("valid fixture gateway IP"),
            },
            vec![RuntimeVolumeConfig {
                volume_id: id("volume_restart_absence"),
                disk_id: id("disk_restart_absence"),
                disk_role: DiskRole::Root,
                size_bytes: 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("restart_root"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
        )
        .expect("valid immutable runtime config");
        LifecycleCommandEnvelope::new(
            id("operation_restart_absence"),
            id("workspace_restart_absence"),
            id("cat_restart_absence"),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config,
            None,
            LifecyclePredecessor::Genesis {
                cat_creation_id: id("creation_restart_absence"),
                target_placement: placement,
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: vec![StartVolumeAuthority {
                    volume_id: id("volume_restart_absence"),
                    disk_id: id("disk_restart_absence"),
                    authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                        expected_unowned_epoch: FenceEpoch::new(0).expect("valid unowned epoch"),
                        transition_id: random(3),
                    },
                }],
                source: StartSource::Genesis,
                effect_deadline_unix_ms: UnixMillis::new(9_000_000).expect("valid effect deadline"),
            })),
        )
        .expect("valid lifecycle command")
    }

    #[test]
    fn complete_socket_scan_accepts_only_manifest_named_socket() {
        let temporary = tempfile::tempdir().expect("create managed-socket fixture");
        let root = temporary.path().join("managed");
        fs::create_dir(&root).expect("create managed socket root");
        let expected_path = root.join("expected.sock");
        let unknown_path = root.join("unknown.sock");
        let _expected = UnixListener::bind(&expected_path).expect("bind expected socket");
        let _unknown = UnixListener::bind(&unknown_path).expect("bind unknown socket");
        let expected = ExpectedGlobalPhysicalArtifacts {
            cat_slices: BTreeMap::new(),
            kernel_nbd: BTreeMap::new(),
            sockets: BTreeSet::from([expected_path]),
        };
        let mut residue = Vec::new();
        classify_unattributed_managed_sockets(
            std::slice::from_ref(&root),
            &expected,
            Instant::now() + Duration::from_secs(1),
            &mut residue,
        )
        .expect("scan complete managed socket tree");
        assert_eq!(residue.len(), 1);
        assert!(residue[0]
            .artifact_id()
            .as_str()
            .starts_with("unattributed-managed-socket-"));
    }

    #[test]
    fn managed_executable_match_preserves_deleted_identity_as_residue() {
        let binary = PathBuf::from("/usr/libexec/cats-blockd");
        let managed = BTreeSet::from([binary.clone()]);
        assert_eq!(
            match_managed_executable(&binary, &managed),
            Some((binary.clone(), false))
        );
        assert_eq!(
            match_managed_executable(Path::new("/usr/libexec/cats-blockd (deleted)"), &managed,),
            Some((binary, true))
        );
        assert!(match_managed_executable(Path::new("/usr/bin/other"), &managed).is_none());
    }

    #[test]
    fn retired_checkpoint_is_quarantined_without_decoding_or_adoption() {
        let temporary = tempfile::tempdir().expect("create retired-checkpoint fixture");
        let checkpoint = temporary.path().join("opaque-old-checkpoint");
        fs::write(&checkpoint, b"not a checkpoint codec").expect("write opaque retired residue");
        let mut residue = Vec::new();
        quarantine_retired_checkpoint_namespace(
            temporary.path(),
            Instant::now() + Duration::from_secs(1),
            &mut residue,
        )
        .expect("classify retired checkpoint namespace");
        assert_eq!(residue.len(), 1);
        assert!(matches!(
            &residue[0],
            ObservedArtifactClassification::QuarantinedForeignOrAmbiguous { artifact_id, .. }
                if artifact_id.as_str().starts_with("retired-runtime-checkpoint-")
        ));
    }

    #[test]
    fn incomplete_start_artifacts_never_remain_adoptable_or_gc_eligible() {
        let artifact_id = Id::new("artifact_a").unwrap();
        let evidence_digest = Sha256Digest::from_bytes([7; 32]);
        let postcondition_digest = Sha256Digest::from_bytes([8; 32]);
        for source in [
            ObservedArtifactClassification::AdoptableCatState {
                artifact_id: artifact_id.clone(),
                ownership_digest: evidence_digest.clone(),
            },
            ObservedArtifactClassification::CatOwnedGcCandidate {
                artifact_id: artifact_id.clone(),
                ownership_digest: evidence_digest.clone(),
                postcondition_digest: postcondition_digest.clone(),
            },
        ] {
            let retained = non_adoptable_progress_artifact(&source);
            assert!(matches!(
                retained,
                ObservedArtifactClassification::RetainedAuthorityOrData {
                    artifact_id: ref retained_id,
                    ..
                } if retained_id == &artifact_id
            ));
        }
        let quarantined = ObservedArtifactClassification::QuarantinedForeignOrAmbiguous {
            artifact_id,
            evidence_digest,
        };
        assert_eq!(non_adoptable_progress_artifact(&quarantined), quarantined);
    }

    #[test]
    fn installed_scan_boundary_calibrates_and_rejects_every_gc_candidate() {
        let artifact_id = Id::new("artifact_candidate").unwrap();
        let candidate = ObservedArtifactClassification::CatOwnedGcCandidate {
            artifact_id,
            ownership_digest: Sha256Digest::from_bytes([21; 32]),
            postcondition_digest: Sha256Digest::from_bytes([22; 32]),
        };
        let mut cat = ObservedCatRuntimeTelemetry {
            cat_id: Id::new("cat_a").unwrap(),
            observed_placement: cats_api::runtime_lifecycle::PlacementIdentity {
                node_id: Id::new("node_a").unwrap(),
                placement_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
            },
            observed_command_journal: None,
            observed_physical_state: ObservedRuntimePhysicalState::StoppedRetained,
            observed_runtime_incarnation: None,
            observed_artifact_manifest_digest: Sha256Digest::from_bytes([23; 32]),
            observed_artifact_classifications: vec![candidate.clone()],
            observed_volumes: Vec::new(),
            observed_conditions: Vec::new(),
        };

        assert!(ensure_no_installed_gc_candidates(std::slice::from_ref(&cat), &[]).is_err());
        assert!(ensure_no_installed_gc_candidates(&[], std::slice::from_ref(&candidate)).is_err());

        cat.observed_artifact_classifications = vec![non_adoptable_progress_artifact(&candidate)];
        ensure_no_installed_gc_candidates(std::slice::from_ref(&cat), &[])
            .expect("incomplete candidate is retained instead of enqueued");
        assert!(matches!(
            &cat.observed_artifact_classifications[0],
            ObservedArtifactClassification::RetainedAuthorityOrData { .. }
        ));
    }

    #[test]
    fn restart_source_absence_is_same_scan_cat_local_and_calibrated() {
        let command = restart_source_command();
        let placement = command.placement_identity.clone();
        let retained = ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: id("artifact_retained_terminal"),
            evidence_digest: digest(31),
        };
        let adoptable = ObservedArtifactClassification::AdoptableCatState {
            artifact_id: id("artifact_runtime_adoptable"),
            ownership_digest: digest(32),
        };
        let target = ObservedCatRuntimeTelemetry {
            cat_id: command.cat_id.clone(),
            observed_placement: placement.clone(),
            observed_command_journal: None,
            observed_physical_state: ObservedRuntimePhysicalState::StoppedRetained,
            observed_runtime_incarnation: None,
            observed_artifact_manifest_digest: digest(33),
            observed_artifact_classifications: vec![adoptable],
            observed_volumes: Vec::new(),
            observed_conditions: Vec::new(),
        };
        let mut inventory = StartupPhysicalInventory::Complete {
            scan_id: random(34),
            collected_at_unix_ms: UnixMillis::new(1).expect("valid collection time"),
            cats: vec![target],
            unattributed_artifacts: Vec::new(),
        };

        assert!(
            installed_restart_source_absence_receipt_digest(&command, &digest(35), &inventory,)
                .is_err()
        );

        let StartupPhysicalInventory::Complete { cats, .. } = &mut inventory else {
            unreachable!("fixture is complete")
        };
        cats[0].observed_artifact_classifications = vec![retained];
        let receipt =
            installed_restart_source_absence_receipt_digest(&command, &digest(35), &inventory)
                .expect("sealed retained carrier is not an armed restart source");

        let mut with_sibling = inventory.clone();
        let StartupPhysicalInventory::Complete { cats, .. } = &mut with_sibling else {
            unreachable!("fixture is complete")
        };
        cats.push(ObservedCatRuntimeTelemetry {
            cat_id: id("cat_sibling_restart_source"),
            observed_placement: cats_api::runtime_lifecycle::PlacementIdentity {
                node_id: id("node_sibling_restart_source"),
                placement_epoch: Epoch::new(1).expect("positive sibling placement epoch"),
            },
            observed_command_journal: None,
            observed_physical_state: ObservedRuntimePhysicalState::Executing,
            observed_runtime_incarnation: Some(random(36)),
            observed_artifact_manifest_digest: digest(37),
            observed_artifact_classifications: vec![
                ObservedArtifactClassification::AdoptableCatState {
                    artifact_id: id("artifact_sibling_adoptable"),
                    ownership_digest: digest(38),
                },
            ],
            observed_volumes: Vec::new(),
            observed_conditions: Vec::new(),
        });
        cats.sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
        assert_eq!(
            installed_restart_source_absence_receipt_digest(&command, &digest(35), &with_sibling,)
                .expect("one sibling restart source cannot suppress the target proof"),
            receipt
        );

        assert_ne!(
            installed_restart_source_absence_receipt_digest(&command, &digest(39), &inventory,)
                .expect("changed journal identity remains a valid distinct proof"),
            receipt
        );
        let mut later_scan = inventory;
        let StartupPhysicalInventory::Complete { scan_id, .. } = &mut later_scan else {
            unreachable!("fixture is complete")
        };
        *scan_id = random(40);
        assert_ne!(
            installed_restart_source_absence_receipt_digest(&command, &digest(35), &later_scan,)
                .expect("later complete scan remains a valid distinct proof"),
            receipt
        );
    }
}
