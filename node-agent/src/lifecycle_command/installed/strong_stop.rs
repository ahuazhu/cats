//! Shared installed strong-Stop edge used by all six command handlers.
//!
//! The outer atomic executor owns journal settlement. This module therefore
//! executes the already-journaled barrier directly and returns exact evidence;
//! it never starts the standalone worker which would complete the journal a
//! second time.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use anyhow::{Context as _, Result};
use cats_api::runtime_inventory::{
    ObservedArtifactClassification, ObservedRuntimeConditionKind, ObservedRuntimePhysicalState,
    ObservedVolumeAttachment, ObservedVolumeWatermark,
};
use cats_api::runtime_lifecycle::{
    ExecutionAbsenceProof, LifecycleCommand, LifecycleCommandEnvelope, LifecycleCommandResponse,
    NodeResult, RetainedEvidence, VolumeTerminalReceipt,
};
use cats_api::runtime_reconciliation::{Id, RandomId128, Sha256Digest, VolumeAdminState};
use cats_storage::authority::{
    validate_volume_owner_binding, validate_volume_record, AttachmentLineageIdentity,
    NodeVolumeInventoryRecord,
};
use cats_storage::lifecycle_volume::{
    command_start_volume_grant_receipt_digest_for_current_owner, LifecycleVolumeCommandScope,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::admission::CloseLifecycleAdmission;

use super::super::executor::LifecycleEffectAuthority;
use super::super::journal::StartupPhysicalInventory;
use super::super::strong_stop::{execute_strong_stop_barrier, StrongStopRequest};
use super::common::InstalledLifecycleContext;
use super::start::{
    AtomicStartFailedVolumeEffect, AtomicStartVolumeGrant, AtomicStartWarmRestartSource,
    InheritedPredecessorPhysicalProjection, InstalledRuntimeProgressManifest,
};

const PHYSICAL_PROJECTION_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.strong-stop-physical-projection.v1";
const EMPTY_RETAINED_MANIFEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.empty-retained-manifest.v1";
const RESTART_SOURCE_POSTCONDITION_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.restart-source-postcondition.v1";

/// Exact evidence returned by the one shared installed strong-Stop edge.
///
/// `post_stop_physical_projection_digest` binds the fresh complete local scan
/// to the command identity and placement. It is execution evidence, not a
/// Control-accepted RuntimeInventoryAttestation. Cold/Delete authorization
/// separately uses a force-Full acceptance bound to current AgentSession.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StrongStopEvidence {
    pub(crate) execution_absence: ExecutionAbsenceProof,
    /// Exact descriptor-authorized Warm revocation/removal receipt before it
    /// is composed with the mandatory post-barrier same-scan absence proof.
    pub(crate) restart_source_cleanup_receipt_digest: Option<Sha256Digest>,
    /// Complete non-executable Warm bundle carrier sealed from the exact
    /// journaled source and the descriptor-authorized cleanup receipt.
    pub(crate) retained_warm_restart_source:
        Option<Box<super::suspend_warm::RetainedWarmRestartSourceCarrier>>,
    pub(crate) stopped_runtime_incarnation: Option<RandomId128>,
    pub(crate) retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    pub(crate) retained_evidence: RetainedEvidence,
    pub(crate) post_stop_physical_projection_digest: Sha256Digest,
}

pub(super) fn execute_command_strong_stop(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    authority: LifecycleEffectAuthority<'_>,
) -> Result<StrongStopEvidence> {
    execute_command_strong_stop_inner(
        ctx,
        command,
        predecessor,
        authority,
        RetainedVolumeReceiptSource::Default,
        None,
    )
}

pub(super) fn execute_command_strong_stop_with_retained_receipts(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    authority: LifecycleEffectAuthority<'_>,
    verified_retained_volume_receipts: Option<&[VolumeTerminalReceipt]>,
) -> Result<StrongStopEvidence> {
    execute_command_strong_stop_inner(
        ctx,
        command,
        predecessor,
        authority,
        verified_retained_volume_receipts.map_or(
            RetainedVolumeReceiptSource::Default,
            RetainedVolumeReceiptSource::Verified,
        ),
        None,
    )
}

pub(super) fn execute_command_strong_stop_with_stop_predecessor(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    predecessor_physical: &super::StopPredecessorPhysical,
    authority: LifecycleEffectAuthority<'_>,
) -> Result<StrongStopEvidence> {
    super::validate_stop_predecessor_physical(command, predecessor, predecessor_physical)?;
    let warm_cleanup_receipt = match &predecessor_physical.source {
        super::StopPredecessorSource::SuspendWarm(physical) => {
            if let Some(cleanup_authority) = physical.warm_cleanup_authority() {
                match ctx
                    .config()
                    .suspend_warm_platform
                    .inspect_or_remove_warm_snapshot(
                        command,
                        cleanup_authority,
                        &super::WarmSnapshotCleanupCompletion::Remove,
                    )? {
                    super::WarmSnapshotCleanupAttempt::Exact(receipt) => Some(receipt),
                    super::WarmSnapshotCleanupAttempt::Blocked => {
                        anyhow::bail!("journaled Warm Stop cleanup authority is stale or ambiguous")
                    }
                }
            } else {
                None
            }
        }
        super::StopPredecessorSource::StartFailed {
            manifest,
            retained_warm_cleanup_authority,
        } => match (
            manifest.retained_warm_restart_source.as_deref(),
            retained_warm_cleanup_authority.as_deref(),
        ) {
            (Some(carrier), Some(cleanup_authority)) => {
                super::validate_start_failed_warm_stop_cleanup_authority(
                    command,
                    predecessor,
                    &manifest.manifest_digest,
                    carrier,
                    cleanup_authority,
                )?;
                match ctx
                    .config()
                    .suspend_warm_platform
                    .inspect_or_remove_warm_snapshot(
                        command,
                        cleanup_authority,
                        &super::WarmSnapshotCleanupCompletion::Remove,
                    )? {
                    super::WarmSnapshotCleanupAttempt::Exact(receipt) => Some(receipt),
                    super::WarmSnapshotCleanupAttempt::Blocked => anyhow::bail!(
                        "journaled retained Warm Stop cleanup authority is stale or ambiguous"
                    ),
                }
            }
            (None, None) => None,
            _ => anyhow::bail!("journaled StartFailed Warm carrier and cleanup authority differ"),
        },
        super::StopPredecessorSource::RetainedTerminal { .. } => None,
    };
    execute_command_strong_stop_inner(
        ctx,
        command,
        Some(predecessor),
        authority,
        RetainedVolumeReceiptSource::Stop(predecessor_physical),
        warm_cleanup_receipt,
    )
}

/// Derive the post-Stop retained subset from the exact Start grants and
/// cumulative progress which are already embedded in the executing failure
/// step. A sequence-zero grant with a complete zero-mutation scan yields the
/// exact current Owned head as `L=R`; every other retained slot requires its
/// materialized lineage. Unproven state never becomes an attachment receipt.
pub(super) struct StartStrongStopInput<'a> {
    pub(super) grants: &'a [AtomicStartVolumeGrant],
    pub(super) progress: Option<&'a InstalledRuntimeProgressManifest>,
    pub(super) failed_volume_effect: Option<&'a AtomicStartFailedVolumeEffect>,
    pub(super) inherited_predecessor_physical: Option<&'a InheritedPredecessorPhysicalProjection>,
    pub(super) warm_restart_source: Option<&'a AtomicStartWarmRestartSource>,
}

pub(super) fn execute_command_strong_stop_with_start_grants(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    authority: LifecycleEffectAuthority<'_>,
    input: StartStrongStopInput<'_>,
) -> Result<StrongStopEvidence> {
    let StartStrongStopInput {
        grants,
        progress,
        failed_volume_effect,
        inherited_predecessor_physical,
        warm_restart_source,
    } = input;
    if let Some(projection) = inherited_predecessor_physical {
        anyhow::ensure!(
            grants.is_empty() && progress.is_none(),
            "inherited predecessor projection accompanied acquired Start progress"
        );
        let failed_volume_effect = failed_volume_effect
            .context("inherited predecessor projection lacks its typed zero-mutation rejection")?;
        super::start::validate_inherited_predecessor_physical_projection(
            command,
            failed_volume_effect,
            projection,
        )?;
        anyhow::ensure!(
            projection.warm_restart_source.as_ref() == warm_restart_source,
            "failed Start changed its journaled Warm predecessor carrier"
        );
    }
    if progress.is_none()
        && failed_volume_effect.is_some_and(|failed| {
            failed.request.actions.iter().any(|action| {
                matches!(
                    action,
                    super::start::AtomicStartVolumeAction::RenewSameNode { .. }
                )
            })
        })
    {
        anyhow::ensure!(
            inherited_predecessor_physical.is_some(),
            "rejected same-Node renewal lacks its journaled predecessor physical projection"
        );
    }
    let warm_cleanup_receipt = if let Some(restart_source) = warm_restart_source {
        match ctx
            .config()
            .suspend_warm_platform
            .inspect_or_remove_warm_snapshot(
                command,
                &restart_source.cleanup_authority,
                &super::WarmSnapshotCleanupCompletion::RetainForFailedStart {
                    inherited_predecessor_physical_digest: restart_source
                        .physical_manifest_digest
                        .clone(),
                },
            )? {
            super::WarmSnapshotCleanupAttempt::Exact(receipt) => Some(receipt),
            super::WarmSnapshotCleanupAttempt::Blocked => anyhow::bail!(
                "journaled Warm StartFailed revocation authority is stale or ambiguous"
            ),
        }
    } else {
        None
    };
    let mut evidence = execute_command_strong_stop_inner(
        ctx,
        command,
        predecessor,
        authority,
        RetainedVolumeReceiptSource::Start {
            grants,
            progress,
            failed_volume_effect,
            inherited_predecessor_physical,
        },
        warm_cleanup_receipt.clone(),
    )?;
    evidence.retained_warm_restart_source = match (warm_restart_source, warm_cleanup_receipt) {
        (Some(restart_source), Some(receipt)) => {
            let carrier = super::suspend_warm::seal_retained_warm_restart_source(
                command,
                &restart_source.cleanup_authority,
                restart_source.physical_manifest_digest.clone(),
                receipt,
            )?;
            super::suspend_warm::validate_retained_warm_restart_source_for_source(
                command,
                &carrier,
                &restart_source.cleanup_authority,
                &restart_source.physical_manifest_digest,
            )?;
            Some(Box::new(carrier))
        }
        (None, None) => None,
        _ => anyhow::bail!("failed Start Warm retention lost its exact cleanup receipt"),
    };
    Ok(evidence)
}

#[derive(Clone, Copy)]
enum RetainedVolumeReceiptSource<'a> {
    Default,
    Verified(&'a [VolumeTerminalReceipt]),
    Stop(&'a super::StopPredecessorPhysical),
    Start {
        grants: &'a [AtomicStartVolumeGrant],
        progress: Option<&'a InstalledRuntimeProgressManifest>,
        failed_volume_effect: Option<&'a AtomicStartFailedVolumeEffect>,
        inherited_predecessor_physical: Option<&'a InheritedPredecessorPhysicalProjection>,
    },
}

fn execute_command_strong_stop_inner(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    authority: LifecycleEffectAuthority<'_>,
    receipt_source: RetainedVolumeReceiptSource<'_>,
    restart_source_cleanup_receipt_digest: Option<Sha256Digest>,
) -> Result<StrongStopEvidence> {
    super::seed_frontend_expectations(ctx, command)
        .context("retain exact restart-safe Guest frontend targets")?;
    let fence = authority
        .stop_fence()
        .context("strong lifecycle effect lacks its retained Stop fence")?;
    let cell = ctx
        .admission_registry()
        .lookup(&command.cat_id)
        .context("look up the Host-global lifecycle admission cell")?
        .context("strong lifecycle effect has no recovered admission cell")?;
    let effective_ready = cell
        .effective_runtime_ready()
        .context("read lifecycle admission before strong Stop")?;
    let admission_request = if let Some(ready) = effective_ready.clone() {
        StrongStopRequest::new(
            CloseLifecycleAdmission::new(command.operation_id.clone(), ready),
            super::dedicated_scope(&command.cat_id)?,
            super::command_grace_deadline(command)?,
        )
    } else {
        StrongStopRequest::new_closed_successor(
            command.operation_id.clone(),
            super::closed_admission_anchor(command, predecessor)?,
            super::dedicated_scope(&command.cat_id)?,
            super::command_grace_deadline(command)?,
        )
    };
    let receipt = execute_strong_stop_barrier(
        fence,
        cell.as_ref(),
        &admission_request,
        ctx.strong_stop_ports(),
    )
    .context("execute installed strong Stop barrier")?;

    // This is a new physical scan after both final absence postconditions and
    // the final fence assertion. It is not the startup scan and it never
    // enumerates the lifecycle-journal namespace.
    let physical = super::scan_startup_inventory(ctx.config())
        .context("collect fresh post-strong-Stop physical evidence")?;
    let scanned_restart_source_absence_receipt_digest =
        super::inventory::installed_restart_source_absence_receipt_digest(
            command,
            fence.journal_content_digest(),
            &physical,
        )
        .context("prove target Cat restart sources absent in post-strong-Stop scan")?;
    let restart_source_absence_receipt_digest = restart_source_postcondition_digest(
        command,
        fence.journal_content_digest(),
        restart_source_cleanup_receipt_digest.as_ref(),
        &scanned_restart_source_absence_receipt_digest,
    );
    let execution_absence = super::execution_absence_proof(
        command,
        fence,
        &receipt,
        restart_source_absence_receipt_digest,
    )?;
    let require_complete_retained_classification = matches!(
        command.command,
        LifecycleCommand::Start(_) | LifecycleCommand::Suspend(_) | LifecycleCommand::Warm(_)
    );
    let (retained_evidence, post_stop_physical_projection_digest) =
        retained_inventory_evidence(command, &physical, require_complete_retained_classification)?;

    let retained_volume_receipts = match receipt_source {
        RetainedVolumeReceiptSource::Verified(receipts) => {
            validate_verified_retained_volume_receipts(ctx, command, receipts)?
        }
        RetainedVolumeReceiptSource::Start {
            grants,
            progress,
            failed_volume_effect,
            inherited_predecessor_physical,
        } => start_retained_volume_receipts(
            ctx,
            command,
            predecessor,
            StartStrongStopInput {
                grants,
                progress,
                failed_volume_effect,
                inherited_predecessor_physical,
                warm_restart_source: None,
            },
            &physical,
        )?,
        RetainedVolumeReceiptSource::Stop(predecessor_physical) => {
            super::safe_stop_volume_receipts(ctx.config(), command, predecessor_physical)?
        }
        RetainedVolumeReceiptSource::Default => Vec::new(),
    };
    let stopped_runtime_incarnation = match receipt_source {
        RetainedVolumeReceiptSource::Stop(predecessor_physical) => {
            predecessor_physical.runtime_incarnation.clone()
        }
        RetainedVolumeReceiptSource::Default
        | RetainedVolumeReceiptSource::Verified(_)
        | RetainedVolumeReceiptSource::Start { .. } => effective_ready
            .map(|ready| ready.runtime_incarnation().clone())
            .or_else(|| predecessor.and_then(predecessor_runtime_incarnation)),
    };

    Ok(StrongStopEvidence {
        execution_absence,
        restart_source_cleanup_receipt_digest,
        retained_warm_restart_source: None,
        stopped_runtime_incarnation,
        retained_volume_receipts,
        retained_evidence,
        post_stop_physical_projection_digest,
    })
}

fn start_retained_volume_receipts(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    input: StartStrongStopInput<'_>,
    physical: &StartupPhysicalInventory,
) -> Result<Vec<VolumeTerminalReceipt>> {
    let StartStrongStopInput {
        grants,
        progress,
        failed_volume_effect,
        inherited_predecessor_physical,
        warm_restart_source: _,
    } = input;
    anyhow::ensure!(
        matches!(command.command, LifecycleCommand::Start(_))
            && grants
                .windows(2)
                .all(|pair| pair[0].volume.volume_id < pair[1].volume.volume_id),
        "failed Start retained grant set is not strictly sorted"
    );
    let Some(progress) = progress else {
        anyhow::ensure!(
            grants.is_empty(),
            "failed Start lost durable progress for acquired Volume grants"
        );
        let failed_volume_effect = failed_volume_effect.context(
            "failed Start without runtime progress lacks typed zero-mutation Volume evidence",
        )?;
        super::start::validate_atomic_start_volume_failure_evidence(
            command,
            &failed_volume_effect.request,
            &failed_volume_effect.evidence,
        )?;
        let rows = load_start_volume_authority(ctx, command)?;
        return rejected_start_retained_volume_receipts(
            ctx,
            command,
            predecessor,
            failed_volume_effect,
            inherited_predecessor_physical,
            &rows,
            physical,
        );
    };
    anyhow::ensure!(
        grants.len() == command.runtime_config.volumes.len()
            && !grants.is_empty()
            && progress.volumes.len() == grants.len()
            && progress.node_id == command.node_id
            && progress.cat_id == command.cat_id
            && progress.placement_identity == command.placement_identity
            && progress.source_lifecycle_operation_id == command.operation_id
            && progress.request_fingerprint == command.request_fingerprint
            && progress.runtime_config_id == command.runtime_config.config_id
            && progress.runtime_config_digest == command.runtime_config.config_digest,
        "failed Start progress does not bind its durable command and grant set"
    );
    super::start::validate_installed_runtime_progress_manifest(progress, command)
        .context("validate failed Start retained runtime progress")?;
    if let Some(failed_volume_effect) = failed_volume_effect {
        super::start::validate_atomic_start_volume_failure_evidence(
            command,
            &failed_volume_effect.request,
            &failed_volume_effect.evidence,
        )?;
    }
    let rows = load_start_volume_authority(ctx, command)?;
    let has_unmaterialized_volume = progress
        .volumes
        .iter()
        .any(|volume| volume.local_lineage_data_directory.is_none());
    if has_unmaterialized_volume {
        let sealed =
            super::start::load_terminal_retained_runtime_manifest(ctx.state_directory(), command)?;
        if let Some(sealed) = sealed.as_ref() {
            anyhow::ensure!(
                sealed.volume_grants == grants
                    && sealed.runtime_progress.as_ref() == Some(progress),
                "sealed retained evidence changed its mixed Executing Start input"
            );
        }
        validate_unmaterialized_start_post_stop_projection(
            ctx.state_directory(),
            command,
            grants,
            progress,
            sealed.as_ref(),
            physical,
        )?;
    }
    let scope = LifecycleVolumeCommandScope {
        operation_id: command.operation_id.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        cat_id: command.cat_id.clone(),
        node_id: command.node_id.clone(),
        placement_identity: command.placement_identity.clone(),
    };
    let mut receipts = Vec::new();
    for ((configured, grant), installed) in command
        .runtime_config
        .volumes
        .iter()
        .zip(grants)
        .zip(&progress.volumes)
    {
        anyhow::ensure!(
            grant.volume.volume_id == configured.volume_id
                && grant.volume.disk_id == configured.disk_id
                && grant.volume.disk_role == configured.disk_role
                && installed.volume_id == configured.volume_id
                && installed.disk_id == configured.disk_id
                && installed.disk_role == configured.disk_role
                && installed.attachment_id == grant.volume.attachment_id
                && installed.attachment_epoch == grant.volume.attachment_epoch
                && installed.acquire_origin == grant.acquire_origin
                && installed.authority_receipt_digest.as_ref() == Some(&grant.grant_receipt_digest),
            "failed Start retained progress changed a Volume grant"
        );
        let row = rows
            .get(&configured.volume_id)
            .context("failed Start retained Volume has no authority row")?;
        let binding = row
            .binding
            .as_ref()
            .context("failed Start retained Volume is already Unowned")?;
        anyhow::ensure!(
            binding.owner_node_id == command.node_id
                && binding.attachment_id == grant.volume.attachment_id
                && binding.attachment_epoch == grant.volume.attachment_epoch
                && super::authority_acquire_origin(&row.volume)? == grant.acquire_origin,
            "failed Start materialized lineage changed owner, epoch, or acquire origin"
        );
        let digest = command_start_volume_grant_receipt_digest_for_current_owner(
            &scope,
            grant.authority_receipt.grant_sequence,
            configured,
            &row.volume,
            &grant.authority_receipt,
        )
        .context("revalidate failed Start immutable grant against current owner")?;
        anyhow::ensure!(
            digest == grant.grant_receipt_digest,
            "failed Start retained immutable grant digest changed"
        );
        let Some(path) = &installed.local_lineage_data_directory else {
            anyhow::ensure!(
                installed.authority_head == grant.authoritative_head
                    && grant.volume.local_durable_generation == grant.authoritative_head.generation
                    && grant.volume.remote_durable_generation
                        == grant.authoritative_head.generation
                    && row.volume.head == grant.authoritative_head,
                "unmaterialized failed Start Volume head changed without a physical writer"
            );
            receipts.push(VolumeTerminalReceipt {
                volume_id: configured.volume_id.clone(),
                disk_id: configured.disk_id.clone(),
                disk_role: configured.disk_role,
                attachment_id: binding.attachment_id.clone(),
                attachment_epoch: binding.attachment_epoch,
                local_durable_generation: row.volume.head.generation,
                remote_durable_generation: row.volume.head.generation,
                authority_receipt_digest: Some(digest),
            });
            continue;
        };
        let identity = AttachmentLineageIdentity {
            volume_id: configured.volume_id.clone(),
            attachment_id: binding.attachment_id.clone(),
            attachment_epoch: binding.attachment_epoch,
            acquire_origin: grant.acquire_origin.clone(),
            node_id: command.node_id.clone(),
            placement_epoch: command.placement_identity.placement_epoch,
        };
        let (local, _) = super::cold_delete::inspect_lineage_durability_read_only(
            Path::new(path.as_str()),
            &identity,
            &row.volume.head,
        )
        .context("inspect failed Start retained local lineage after strong Stop")?;
        receipts.push(VolumeTerminalReceipt {
            volume_id: configured.volume_id.clone(),
            disk_id: configured.disk_id.clone(),
            disk_role: configured.disk_role,
            attachment_id: binding.attachment_id.clone(),
            attachment_epoch: binding.attachment_epoch,
            local_durable_generation: local,
            remote_durable_generation: row.volume.head.generation,
            authority_receipt_digest: Some(digest),
        });
    }
    anyhow::ensure!(
        receipts.len() == grants.len()
            && receipts
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "failed Start retained receipt set is incomplete or not strictly sorted"
    );
    Ok(receipts)
}

fn load_start_volume_authority(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
) -> Result<BTreeMap<Id, NodeVolumeInventoryRecord>> {
    let candidates = command
        .runtime_config
        .volumes
        .iter()
        .map(|volume| volume.volume_id.clone())
        .collect::<BTreeSet<_>>();
    let snapshot = ctx
        .volume_inventory_authority()
        .load_node_volume_inventory(ctx.node_id(), &candidates)
        .context("reload failed Start retained Volume authority")?;
    anyhow::ensure!(
        snapshot.node_id == command.node_id,
        "failed Start retained Volume snapshot belongs to another Node"
    );
    let mut rows = BTreeMap::new();
    for entry in snapshot.records {
        validate_volume_record(&entry.volume)
            .context("validate failed Start retained Volume row")?;
        if let Some(binding) = &entry.binding {
            validate_volume_owner_binding(binding, &entry.volume)
                .context("validate failed Start retained owner binding")?;
        }
        anyhow::ensure!(
            rows.insert(entry.volume.volume_id.clone(), entry).is_none(),
            "failed Start retained Volume snapshot repeats a row"
        );
    }
    anyhow::ensure!(
        candidates.iter().all(|volume| rows.contains_key(volume)),
        "failed Start retained Volume snapshot omitted a candidate"
    );
    Ok(rows)
}

fn rejected_start_retained_volume_receipts(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    failed_volume_effect: &AtomicStartFailedVolumeEffect,
    inherited_predecessor_physical: Option<&InheritedPredecessorPhysicalProjection>,
    rows: &BTreeMap<Id, NodeVolumeInventoryRecord>,
    physical: &StartupPhysicalInventory,
) -> Result<Vec<VolumeTerminalReceipt>> {
    anyhow::ensure!(
        failed_volume_effect.request.grant_sequence.get() == 0
            && failed_volume_effect.request.actions.len() == command.runtime_config.volumes.len(),
        "zero-progress failed Start is not an exact initial Volume batch rejection"
    );
    let installed = super::retained_volume_physical_evidence(ctx.config(), command)?;
    if let Some(projection) = inherited_predecessor_physical {
        return inherited_rejected_start_retained_volume_receipts(
            command,
            failed_volume_effect,
            projection,
            rows,
            &installed,
        );
    }
    let predecessor_receipts = rejected_start_predecessor_receipts(ctx, command, predecessor)?;
    let mut receipts = Vec::new();
    for configured in &command.runtime_config.volumes {
        let row = rows
            .get(&configured.volume_id)
            .context("rejected failed Start Volume has no fresh authority row")?;
        anyhow::ensure!(
            matches!(row.volume.admin_state, VolumeAdminState::Active),
            "rejected failed Start Volume is not Active"
        );
        let Some(binding) = row.binding.as_ref() else {
            anyhow::ensure!(
                row.volume.lease_owner.is_none() && row.volume.lease_expires_at.is_none(),
                "rejected failed Start has an unbound owner projection"
            );
            continue;
        };
        if binding.owner_node_id != command.node_id {
            continue;
        }
        let previous = predecessor_receipts
            .get(&configured.volume_id)
            .context("rejected failed Start left this Node Owned without a predecessor receipt")?;
        let authority_receipt_digest = previous
            .authority_receipt_digest
            .as_ref()
            .context("rejected failed Start predecessor lacks its immutable StartGrant digest")?;
        anyhow::ensure!(
            previous.disk_id == configured.disk_id
                && previous.disk_role == configured.disk_role
                && previous.attachment_id == binding.attachment_id
                && previous.attachment_epoch == binding.attachment_epoch
                && previous.remote_durable_generation <= previous.local_durable_generation
                && row.volume.head.generation >= previous.remote_durable_generation,
            "rejected failed Start predecessor changed config, owner, epoch, or remote lineage"
        );
        let (local, remote) = if let Some(installed) = installed.get(&configured.volume_id) {
            anyhow::ensure!(
                installed.disk_id == configured.disk_id
                    && installed.disk_role == configured.disk_role
                    && installed.attachment_id == binding.attachment_id
                    && installed.attachment_epoch == binding.attachment_epoch
                    && installed.acquire_origin == super::authority_acquire_origin(&row.volume)?
                    && &installed.authority_receipt_digest == authority_receipt_digest,
                "rejected failed Start installed lineage changed its predecessor authority"
            );
            let identity = AttachmentLineageIdentity {
                volume_id: configured.volume_id.clone(),
                attachment_id: binding.attachment_id.clone(),
                attachment_epoch: binding.attachment_epoch,
                acquire_origin: installed.acquire_origin.clone(),
                node_id: command.node_id.clone(),
                placement_epoch: command.placement_identity.placement_epoch,
            };
            let (local, _) = super::cold_delete::inspect_lineage_durability_read_only(
                &installed.local_lineage_data_directory,
                &identity,
                &row.volume.head,
            )
            .context("inspect same-Node lineage after rejected Start")?;
            (local, row.volume.head.generation)
        } else {
            anyhow::ensure!(
                previous.local_durable_generation == previous.remote_durable_generation
                    && previous.remote_durable_generation == row.volume.head.generation,
                "rejected failed Start lacks fresh lineage for a retained local durability tail"
            );
            (row.volume.head.generation, row.volume.head.generation)
        };
        receipts.push(VolumeTerminalReceipt {
            volume_id: configured.volume_id.clone(),
            disk_id: configured.disk_id.clone(),
            disk_role: configured.disk_role,
            attachment_id: binding.attachment_id.clone(),
            attachment_epoch: binding.attachment_epoch,
            local_durable_generation: local,
            remote_durable_generation: remote,
            authority_receipt_digest: Some(authority_receipt_digest.clone()),
        });
    }
    if receipts.is_empty() {
        let StartupPhysicalInventory::Complete {
            cats,
            unattributed_artifacts,
            ..
        } = physical
        else {
            anyhow::bail!("rejected failed Start requires a complete post-stop scan")
        };
        anyhow::ensure!(
            unattributed_artifacts.is_empty()
                && !cats.iter().any(|cat| cat.cat_id == command.cat_id),
            "rejected failed Start has target-Node retained or unknown physical artifacts"
        );
        ensure_cat_lineage_root_absent(ctx.state_directory(), &command.cat_id)?;
    }
    anyhow::ensure!(
        receipts
            .windows(2)
            .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "rejected failed Start retained receipts are not strictly sorted"
    );
    Ok(receipts)
}

/// Join the pre-Stop predecessor carrier to a new post-Stop authority read.
///
/// This path deliberately does not consult `CommandFailed` receipt counts or
/// rediscover a predecessor manifest after the physical effect. The carrier
/// was validated and journaled before strong Stop; the fresh authority row
/// decides whether that exact Owned lineage is still retained. A materialized
/// lineage is opened through its exact carrier path and identity. A proven
/// absent lineage may only remain at the carrier head and therefore seals
/// `L == R == head`.
fn inherited_rejected_start_retained_volume_receipts(
    command: &LifecycleCommandEnvelope,
    failed_volume_effect: &AtomicStartFailedVolumeEffect,
    projection: &InheritedPredecessorPhysicalProjection,
    rows: &BTreeMap<Id, NodeVolumeInventoryRecord>,
    installed: &BTreeMap<Id, super::RetainedVolumePhysicalEvidence>,
) -> Result<Vec<VolumeTerminalReceipt>> {
    super::start::validate_inherited_predecessor_physical_projection(
        command,
        failed_volume_effect,
        projection,
    )?;

    let mut receipts = Vec::with_capacity(projection.volumes.len());
    for configured in &command.runtime_config.volumes {
        let row = rows
            .get(&configured.volume_id)
            .context("inherited failed Start Volume has no fresh authority row")?;
        anyhow::ensure!(
            matches!(row.volume.admin_state, VolumeAdminState::Active),
            "inherited failed Start Volume is not Active"
        );
        let Some(binding) = row.binding.as_ref() else {
            anyhow::ensure!(
                row.volume.lease_owner.is_none() && row.volume.lease_expires_at.is_none(),
                "inherited failed Start has an unbound owner projection"
            );
            continue;
        };
        if binding.owner_node_id != command.node_id {
            continue;
        }

        let physical = projection
            .volumes
            .binary_search_by(|volume| volume.volume_id.cmp(&configured.volume_id))
            .ok()
            .map(|index| &projection.volumes[index])
            .context(
                "rejected same-Node renewal left this Node Owned outside its journaled predecessor projection",
            )?;
        let current_origin = super::authority_acquire_origin(&row.volume)?;
        anyhow::ensure!(
            physical.disk_id == configured.disk_id
                && physical.disk_role == configured.disk_role
                && physical.attachment_id == binding.attachment_id
                && physical.attachment_epoch == binding.attachment_epoch
                && physical.acquire_origin == current_origin
                && row.volume.head.generation >= physical.authoritative_head.generation
                && (row.volume.head.generation != physical.authoritative_head.generation
                    || row.volume.head == physical.authoritative_head),
            "rejected same-Node renewal changed config, owner, epoch, origin, or remote lineage"
        );

        let (local, remote) = match &physical.local_lineage_data_directory {
            Some(path) => {
                let installed = installed.get(&configured.volume_id).context(
                    "materialized inherited lineage lacks fresh installed physical evidence",
                )?;
                anyhow::ensure!(
                    installed.disk_id == physical.disk_id
                        && installed.disk_role == physical.disk_role
                        && installed.attachment_id == physical.attachment_id
                        && installed.attachment_epoch == physical.attachment_epoch
                        && installed.acquire_origin == physical.acquire_origin
                        && installed.authority_receipt_digest
                            == physical.immutable_start_grant_receipt_digest
                        && installed.local_lineage_data_directory == Path::new(path.as_str()),
                    "installed inherited lineage conflicts with its pre-Stop physical carrier"
                );
                let identity = AttachmentLineageIdentity {
                    volume_id: configured.volume_id.clone(),
                    attachment_id: binding.attachment_id.clone(),
                    attachment_epoch: binding.attachment_epoch,
                    acquire_origin: physical.acquire_origin.clone(),
                    node_id: command.node_id.clone(),
                    placement_epoch: command.placement_identity.placement_epoch,
                };
                let (local, _) = super::cold_delete::inspect_lineage_durability_read_only(
                    Path::new(path.as_str()),
                    &identity,
                    &row.volume.head,
                )
                .context("inspect inherited same-Node lineage after strong Stop")?;
                (local, row.volume.head.generation)
            }
            None => {
                anyhow::ensure!(
                    row.volume.head == physical.authoritative_head
                        && !installed.contains_key(&configured.volume_id),
                    "absent inherited lineage advanced or gained installed physical evidence"
                );
                (row.volume.head.generation, row.volume.head.generation)
            }
        };
        receipts.push(VolumeTerminalReceipt {
            volume_id: configured.volume_id.clone(),
            disk_id: configured.disk_id.clone(),
            disk_role: configured.disk_role,
            attachment_id: binding.attachment_id.clone(),
            attachment_epoch: binding.attachment_epoch,
            local_durable_generation: local,
            remote_durable_generation: remote,
            authority_receipt_digest: Some(physical.immutable_start_grant_receipt_digest.clone()),
        });
    }

    anyhow::ensure!(
        receipts.len() == projection.volumes.len()
            && receipts
                .iter()
                .zip(&projection.volumes)
                .all(|(receipt, physical)| receipt.volume_id == physical.volume_id),
        "rejected same-Node renewal changed the exact predecessor Owned Volume set"
    );
    Ok(receipts)
}

fn ensure_cat_lineage_root_absent(
    state_directory: &crate::state_directory::StateDirectory,
    cat_id: &Id,
) -> Result<()> {
    let state = state_directory
        .try_clone_directory()
        .context("reopen anchored state directory for rejected Start absence")?;
    let data_name = CString::new("data").expect("static state child has no NUL");
    // SAFETY: `state` is live for the call, the C string is terminated, and a
    // successful descriptor is immediately owned by `File` below.
    let data_fd = unsafe {
        libc::openat(
            state.as_raw_fd(),
            data_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if data_fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error).context("open no-follow state data namespace");
    }
    // SAFETY: successful `openat` returned one newly-owned descriptor.
    let data = unsafe { File::from_raw_fd(data_fd) };
    let cat_name = CString::new(format!("cat-{cat_id}"))
        .context("rejected Start Cat lineage basename contains NUL")?;
    // O_NONBLOCK prevents a foreign FIFO/device from blocking this absence
    // probe. Any result other than ENOENT is residue or ambiguity.
    // SAFETY: `data` and `cat_name` remain live for the call; a successful fd
    // is immediately closed by wrapping it in `File`.
    let cat_fd = unsafe {
        libc::openat(
            data.as_raw_fd(),
            cat_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
    };
    if cat_fd >= 0 {
        // SAFETY: successful `openat` returned one newly-owned descriptor.
        drop(unsafe { File::from_raw_fd(cat_fd) });
        anyhow::bail!("rejected failed Start retains a Cat-local lineage namespace")
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        return Ok(());
    }
    Err(error).context("prove rejected Start Cat-local lineage namespace absent")
}

fn rejected_start_predecessor_receipts(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
) -> Result<BTreeMap<Id, VolumeTerminalReceipt>> {
    let Some(predecessor) = predecessor else {
        return Ok(BTreeMap::new());
    };
    if let NodeResult::StartFailed(failed) = &predecessor.result {
        let mut matching = Vec::new();
        for entry in
            super::start::enumerate_installed_start_physical_manifests(ctx.state_directory())?
        {
            let super::start::InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest) =
                entry
            else {
                continue;
            };
            if manifest.cat_id == command.cat_id
                && manifest.source_lifecycle_operation_id == predecessor.operation_id
            {
                matching.push(manifest);
            }
        }
        if matching.is_empty() {
            return Ok(BTreeMap::new());
        }
        let [manifest] = matching.as_slice() else {
            anyhow::bail!("rejected Start found multiple retained predecessor manifests")
        };
        super::start::validate_terminal_retained_runtime_manifest(manifest, None)?;
        anyhow::ensure!(
            manifest.node_id == command.node_id
                && manifest.placement_identity == command.placement_identity
                && manifest.runtime_config_id == command.runtime_config.config_id
                && manifest.runtime_config_digest == command.runtime_config.config_digest
                && failed.retained_evidence.artifact_manifest_digest == manifest.manifest_digest,
            "rejected Start retained predecessor changed terminal or runtime identity"
        );
        return Ok(manifest
            .retained_volume_receipts
            .iter()
            .cloned()
            .map(|receipt| (receipt.volume_id.clone(), receipt))
            .collect());
    }
    let mut receipts = BTreeMap::new();
    for receipt in super::predecessor_retained_volume_receipts(predecessor) {
        anyhow::ensure!(
            receipts
                .insert(receipt.volume_id.clone(), receipt.clone())
                .is_none(),
            "rejected Start predecessor repeats a retained Volume"
        );
    }
    Ok(receipts)
}

fn validate_unmaterialized_start_post_stop_projection(
    state_directory: &crate::state_directory::StateDirectory,
    command: &LifecycleCommandEnvelope,
    grants: &[AtomicStartVolumeGrant],
    progress: &InstalledRuntimeProgressManifest,
    sealed: Option<&super::start::TerminalRetainedRuntimeManifest>,
    physical: &StartupPhysicalInventory,
) -> Result<()> {
    anyhow::ensure!(
        grants.len() == progress.volumes.len()
            && grants
                .iter()
                .zip(&progress.volumes)
                .any(|(_, volume)| { volume.local_lineage_data_directory.is_none() }),
        "failed Start has no unmaterialized Volume slot to prove absent"
    );
    for (grant, installed) in grants.iter().zip(&progress.volumes) {
        if installed.local_lineage_data_directory.is_some() {
            continue;
        }
        anyhow::ensure!(
            installed.blockd.is_none()
                && installed.blockd_control_socket_path.is_none()
                && installed.frontend.is_none()
                && installed.authority_head == grant.authoritative_head
                && grant.volume.local_durable_generation == grant.authoritative_head.generation
                && grant.volume.remote_durable_generation == grant.authoritative_head.generation,
            "unmaterialized failed Start slot contains a physical identity or changed head"
        );
        ensure_descriptor_relative_path_absent(
            state_directory,
            &grant.planned_local_lineage_data_directory,
        )?;
    }
    let StartupPhysicalInventory::Complete {
        cats,
        unattributed_artifacts,
        ..
    } = physical
    else {
        anyhow::bail!("unmaterialized failed Start requires a complete post-stop scan")
    };
    anyhow::ensure!(
        unattributed_artifacts.is_empty(),
        "unmaterialized failed Start scan contains unattributed physical artifacts"
    );
    let matches = cats
        .iter()
        .filter(|cat| cat.cat_id == command.cat_id)
        .collect::<Vec<_>>();
    let [cat] = matches.as_slice() else {
        anyhow::bail!("unmaterialized failed Start lacks one exact Cat projection")
    };
    let mut expected_artifacts = progress.artifact_classifications.clone();
    anyhow::ensure!(
        expected_artifacts.len() == grants.len()
            && expected_artifacts.iter().all(|artifact| matches!(
                artifact,
                ObservedArtifactClassification::RetainedAuthorityOrData { .. }
            )),
        "unmaterialized failed Start progress contains non-StartGrant artifacts"
    );
    let (expected_condition, expected_known_watermark) = if let Some(sealed) = sealed {
        expected_artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: super::artifact_id(
                "terminal-retained-start",
                sealed.manifest_digest.as_bytes(),
            )?,
            evidence_digest: sealed.manifest_digest.clone(),
        });
        expected_artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: super::artifact_id(
                "terminal-retained-physical-evidence",
                sealed
                    .physical_retained_evidence
                    .artifact_manifest_digest
                    .as_bytes(),
            )?,
            evidence_digest: sealed
                .physical_retained_evidence
                .artifact_manifest_digest
                .clone(),
        });
        (ObservedRuntimeConditionKind::Blocked, true)
    } else {
        expected_artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: super::artifact_id(
                "atomic-start-progress",
                command.cat_id.as_str().as_bytes(),
            )?,
            evidence_digest: progress.manifest_digest.clone(),
        });
        (ObservedRuntimeConditionKind::Progressing, false)
    };
    expected_artifacts.sort_by(|left, right| left.artifact_id().cmp(right.artifact_id()));
    anyhow::ensure!(
        expected_artifacts
            .windows(2)
            .all(|pair| pair[0].artifact_id() < pair[1].artifact_id()),
        "unmaterialized failed Start expected artifacts are not a strict set"
    );
    anyhow::ensure!(
        cat.observed_placement == command.placement_identity
            && cat.observed_command_journal.is_none()
            && cat.observed_physical_state == ObservedRuntimePhysicalState::StoppedRetained
            && cat.observed_runtime_incarnation.is_none()
            && cat.observed_artifact_classifications == expected_artifacts
            && cat.observed_conditions.len() == 1
            && cat.observed_conditions[0].kind == expected_condition
            && cat.observed_conditions[0].evidence_digest == cat.observed_artifact_manifest_digest
            && cat.observed_volumes.len() == grants.len(),
        "unmaterialized failed Start scan contains physical mutation or ambiguous evidence"
    );
    for ((observed, grant), installed) in cat
        .observed_volumes
        .iter()
        .zip(grants)
        .zip(&progress.volumes)
    {
        let watermark_is_closed = match (
            expected_known_watermark,
            &installed.local_lineage_data_directory,
            &observed.observed_watermark,
        ) {
            (false, _, ObservedVolumeWatermark::Unknown { .. }) => true,
            (
                true,
                None,
                ObservedVolumeWatermark::Known {
                    local_durable_generation,
                    remote_durable_generation,
                },
            ) => {
                *local_durable_generation == grant.authoritative_head.generation
                    && *remote_durable_generation == grant.authoritative_head.generation
            }
            (true, Some(_), ObservedVolumeWatermark::Known { .. }) => true,
            _ => false,
        };
        anyhow::ensure!(
            observed.volume_id == grant.volume.volume_id
                && observed.disk_id == grant.volume.disk_id
                && observed.disk_role == grant.volume.disk_role
                && observed.observed_attachment
                    == ObservedVolumeAttachment::Owned {
                        owner_node_id: command.node_id.clone(),
                        attachment_id: grant.volume.attachment_id.clone(),
                        attachment_epoch: grant.volume.attachment_epoch,
                    }
                && watermark_is_closed,
            "unmaterialized failed Start scan changed a Volume owner or exposed physical L/R"
        );
    }
    Ok(())
}

fn ensure_descriptor_relative_path_absent(
    state_directory: &crate::state_directory::StateDirectory,
    target: &cats_api::runtime_reconciliation::HostPath,
) -> Result<()> {
    let target = Path::new(target.as_str());
    let relative = target
        .strip_prefix(state_directory.path())
        .context("unmaterialized Start lineage target is outside StateDirectory")?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => CString::new(name.as_encoded_bytes())
                .context("unmaterialized Start lineage component contains NUL"),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => {
                anyhow::bail!("unmaterialized Start lineage target is not canonical")
            }
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        !components.is_empty(),
        "unmaterialized Start lineage target is the StateDirectory root"
    );
    let mut directory = state_directory
        .try_clone_directory()
        .context("reopen anchored StateDirectory for lineage absence")?;
    let mut opened_identities = Vec::with_capacity(components.len());
    for (missing_index, component) in components.iter().enumerate() {
        let Some(next) = open_directory_component_optional(&directory, component)? else {
            // Reopen the canonical StateDirectory and repeat the complete
            // prefix traversal. Equal dev/inode identities close an ancestor
            // rename/replacement window before the second absence check.
            let mut replay = state_directory
                .try_reopen_directory()
                .context("revalidate anchored StateDirectory for lineage absence")?;
            for (expected, prefix) in opened_identities.iter().zip(&components[..missing_index]) {
                let current = open_directory_component_optional(&replay, prefix)?.context(
                    "unmaterialized Start lineage ancestor disappeared during absence proof",
                )?;
                anyhow::ensure!(
                    directory_file_identity(&current)? == *expected,
                    "unmaterialized Start lineage ancestor changed identity"
                );
                replay = current;
            }
            anyhow::ensure!(
                open_directory_component_optional(&replay, component)?.is_none(),
                "unmaterialized Start lineage appeared during absence proof"
            );
            return Ok(());
        };
        opened_identities.push(directory_file_identity(&next)?);
        directory = next;
    }
    anyhow::bail!("unmaterialized failed Start has its planned local lineage artifact")
}

fn open_directory_component_optional(directory: &File, name: &CString) -> Result<Option<File>> {
    // O_DIRECTORY rejects a file/device/FIFO, O_NOFOLLOW rejects a replacement
    // symlink, and O_NONBLOCK prevents a hostile special file from stalling
    // the post-Stop proof.
    // SAFETY: `directory` and the terminated component name remain live; a
    // successful descriptor is immediately owned by `File`.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
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
        // SAFETY: successful `openat` returned one newly-owned descriptor.
        return Ok(Some(unsafe { File::from_raw_fd(descriptor) }));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        return Ok(None);
    }
    Err(error).context("descriptor-relative unmaterialized Start lineage traversal is ambiguous")
}

fn directory_file_identity(directory: &File) -> Result<(u64, u64)> {
    let metadata = directory
        .metadata()
        .context("inspect unmaterialized Start lineage directory identity")?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "unmaterialized Start lineage component is not a directory"
    );
    Ok((metadata.dev(), metadata.ino()))
}

fn validate_verified_retained_volume_receipts(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    receipts: &[VolumeTerminalReceipt],
) -> Result<Vec<VolumeTerminalReceipt>> {
    anyhow::ensure!(
        receipts
            .windows(2)
            .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "strong Stop retained Volume receipts are not strictly sorted"
    );
    let configured = command
        .runtime_config
        .volumes
        .iter()
        .map(|volume| (volume.volume_id.clone(), volume))
        .collect::<std::collections::BTreeMap<_, _>>();
    let candidates = configured.keys().cloned().collect();
    let snapshot = ctx
        .volume_inventory_authority()
        .load_node_volume_inventory(ctx.node_id(), &candidates)
        .context("reload Volume authority for retained strong Stop receipts")?;
    anyhow::ensure!(
        snapshot.node_id == *ctx.node_id(),
        "retained strong Stop Volume snapshot belongs to another Node"
    );
    let mut rows = std::collections::BTreeMap::new();
    for entry in &snapshot.records {
        validate_volume_record(&entry.volume)
            .context("validate retained strong Stop Volume authority row")?;
        anyhow::ensure!(
            rows.insert(entry.volume.volume_id.clone(), entry).is_none(),
            "retained strong Stop Volume snapshot contains duplicate rows"
        );
    }
    for receipt in receipts {
        let config = configured
            .get(&receipt.volume_id)
            .context("retained strong Stop receipt is outside runtime config")?;
        let entry = rows
            .get(&receipt.volume_id)
            .context("retained strong Stop receipt has no fresh authority row")?;
        let binding = entry
            .binding
            .as_ref()
            .context("retained strong Stop receipt names an Unowned Volume")?;
        validate_volume_owner_binding(binding, &entry.volume)
            .context("validate retained strong Stop owner binding")?;
        anyhow::ensure!(
            binding.owner_node_id == *ctx.node_id()
                && receipt.disk_id == config.disk_id
                && receipt.disk_role == config.disk_role
                && receipt.attachment_id == binding.attachment_id
                && receipt.attachment_epoch == binding.attachment_epoch
                && receipt.authority_receipt_digest.is_some()
                && receipt.remote_durable_generation <= receipt.local_durable_generation
                && entry.volume.head.generation >= receipt.remote_durable_generation,
            "retained strong Stop receipt changed its config, owner, epoch, or durability lineage"
        );
    }
    if matches!(
        command.command,
        LifecycleCommand::Suspend(_) | LifecycleCommand::Warm(_)
    ) {
        let exact = installed_runtime_retained_volume_receipts(ctx, command)?;
        let mut exact_index = 0_usize;
        for observed in receipts {
            while exact_index < exact.len() && exact[exact_index].volume_id < observed.volume_id {
                exact_index += 1;
            }
            let current = exact
                .get(exact_index)
                .context("retained Suspend/Warm receipt is outside exact installed state")?;
            anyhow::ensure!(
                current.volume_id == observed.volume_id
                    && current.disk_id == observed.disk_id
                    && current.disk_role == observed.disk_role
                    && current.attachment_id == observed.attachment_id
                    && current.attachment_epoch == observed.attachment_epoch
                    && current.authority_receipt_digest == observed.authority_receipt_digest
                    && current.local_durable_generation >= observed.local_durable_generation
                    && current.remote_durable_generation >= observed.remote_durable_generation,
                "exact post-Stop Suspend/Warm receipt changed or regressed observed lineage"
            );
            exact_index += 1;
        }
        return Ok(exact);
    }
    Ok(receipts.to_vec())
}

/// Recover the complete failed Suspend/Warm carrier from Node-owned durable
/// state after the shared strong-Stop barrier. This is intentionally not a
/// projection of Control's current rows: every receipt joins the sealed
/// installed RuntimeReady manifest, a fresh owner/epoch/head read, and the
/// exact local lineage watermark. A missing or changed slot keeps the command
/// unresolved instead of manufacturing an incomplete retry authority.
fn installed_runtime_retained_volume_receipts(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
) -> Result<Vec<VolumeTerminalReceipt>> {
    let manifest =
        super::start::load_installed_runtime_manifest(ctx.state_directory(), &command.cat_id)?
            .context("failed Suspend/Warm lost its installed RuntimeReady manifest")?;
    anyhow::ensure!(
        manifest.node_id == command.node_id
            && manifest.cat_id == command.cat_id
            && manifest.placement_identity == command.placement_identity
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest
            && manifest.volumes.len() == command.runtime_config.volumes.len(),
        "failed Suspend/Warm installed manifest changed its immutable runtime target"
    );

    let candidates = command
        .runtime_config
        .volumes
        .iter()
        .map(|volume| volume.volume_id.clone())
        .collect::<BTreeSet<_>>();
    let snapshot = ctx
        .volume_inventory_authority()
        .load_node_volume_inventory(ctx.node_id(), &candidates)
        .context("load failed Suspend/Warm Volume authority snapshot")?;
    anyhow::ensure!(
        snapshot.node_id == *ctx.node_id(),
        "failed Suspend/Warm Volume snapshot belongs to another Node"
    );
    let mut rows = BTreeMap::new();
    for entry in snapshot.records {
        validate_volume_record(&entry.volume)
            .context("validate failed Suspend/Warm Volume authority row")?;
        if let Some(binding) = &entry.binding {
            validate_volume_owner_binding(binding, &entry.volume)
                .context("validate failed Suspend/Warm owner binding")?;
        }
        anyhow::ensure!(
            rows.insert(entry.volume.volume_id.clone(), entry).is_none(),
            "failed Suspend/Warm Volume snapshot repeats a row"
        );
    }

    let mut receipts = Vec::with_capacity(command.runtime_config.volumes.len());
    for (configured, installed) in command.runtime_config.volumes.iter().zip(&manifest.volumes) {
        let entry = rows
            .get(&configured.volume_id)
            .context("failed Suspend/Warm Volume snapshot omitted a configured slot")?;
        let binding = entry
            .binding
            .as_ref()
            .context("failed Suspend/Warm configured Volume is no longer Owned")?;
        let grant_digest = installed
            .authority_receipt_digest
            .as_ref()
            .context("failed Suspend/Warm installed Volume lacks its StartGrant digest")?;
        anyhow::ensure!(
            matches!(entry.volume.admin_state, VolumeAdminState::Active)
                && installed.volume_id == configured.volume_id
                && installed.disk_id == configured.disk_id
                && installed.disk_role == configured.disk_role
                && entry.volume.size_bytes == configured.size_bytes
                && entry.volume.durability == configured.durability
                && binding.owner_node_id == command.node_id
                && binding.attachment_id == installed.attachment_id
                && binding.attachment_epoch == installed.attachment_epoch
                && super::authority_acquire_origin(&entry.volume)? == installed.acquire_origin
                && entry.volume.head.generation >= installed.current_authority_head.generation
                && (entry.volume.head.generation != installed.current_authority_head.generation
                    || entry.volume.head == installed.current_authority_head)
                && grant_digest.as_bytes().iter().any(|byte| *byte != 0),
            "failed Suspend/Warm Volume changed config, owner, epoch, grant, or remote lineage"
        );
        let identity = AttachmentLineageIdentity {
            volume_id: configured.volume_id.clone(),
            attachment_id: binding.attachment_id.clone(),
            attachment_epoch: binding.attachment_epoch,
            acquire_origin: installed.acquire_origin.clone(),
            node_id: command.node_id.clone(),
            placement_epoch: command.placement_identity.placement_epoch,
        };
        let (local, _) = super::cold_delete::inspect_lineage_durability_read_only(
            Path::new(installed.local_lineage_data_directory.as_str()),
            &identity,
            &entry.volume.head,
        )
        .context("inspect failed Suspend/Warm retained local lineage")?;
        anyhow::ensure!(
            local >= entry.volume.head.generation,
            "failed Suspend/Warm local lineage is behind current authority"
        );
        receipts.push(VolumeTerminalReceipt {
            volume_id: configured.volume_id.clone(),
            disk_id: configured.disk_id.clone(),
            disk_role: configured.disk_role,
            attachment_id: binding.attachment_id.clone(),
            attachment_epoch: binding.attachment_epoch,
            local_durable_generation: local,
            remote_durable_generation: entry.volume.head.generation,
            authority_receipt_digest: Some(grant_digest.clone()),
        });
    }
    anyhow::ensure!(
        receipts.len() == command.runtime_config.volumes.len()
            && receipts
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "failed Suspend/Warm retained Volume carrier is incomplete or non-canonical"
    );
    Ok(receipts)
}

pub(super) fn retained_inventory_evidence(
    command: &LifecycleCommandEnvelope,
    inventory: &StartupPhysicalInventory,
    require_complete_retained_classification: bool,
) -> Result<(RetainedEvidence, Sha256Digest)> {
    let StartupPhysicalInventory::Complete {
        scan_id,
        collected_at_unix_ms,
        cats,
        unattributed_artifacts,
    } = inventory
    else {
        anyhow::bail!("post-strong-Stop physical inventory is incomplete")
    };
    anyhow::ensure!(
        cats.windows(2).all(|pair| pair[0].cat_id < pair[1].cat_id),
        "post-strong-Stop Cat inventory is not strictly sorted"
    );
    anyhow::ensure!(
        unattributed_artifacts
            .windows(2)
            .all(|pair| pair[0].artifact_id() < pair[1].artifact_id()),
        "post-strong-Stop unattributed artifacts are not strictly sorted"
    );

    let projection_value = serde_json::json!({
        "version": 1,
        "operation_id": command.operation_id,
        "request_fingerprint": command.request_fingerprint,
        "cat_id": command.cat_id,
        "node_id": command.node_id,
        "placement_identity": command.placement_identity,
        "scan_id": scan_id,
        "collected_at_unix_ms": collected_at_unix_ms,
        "cats": cats,
        "unattributed_artifacts": unattributed_artifacts,
    });
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&projection_value);
    let post_stop_physical_projection_digest =
        digest_parts(PHYSICAL_PROJECTION_DOMAIN, &[&canonical]);

    // A terminal failure's retained evidence is a complete Cat-local
    // classification. Unknown Host artifacts cannot be attributed to this
    // Cat and therefore keep the command unresolved rather than being counted
    // or silently omitted.
    if require_complete_retained_classification {
        anyhow::ensure!(
            unattributed_artifacts.is_empty(),
            "post-strong-Stop inventory still contains unattributed physical artifacts"
        );
    }
    let cat = cats.iter().find(|cat| cat.cat_id == command.cat_id);
    let (manifest_digest, artifacts) = match cat {
        Some(cat) => (
            cat.observed_artifact_manifest_digest.clone(),
            cat.observed_artifact_classifications.as_slice(),
        ),
        None => (
            digest_parts(
                EMPTY_RETAINED_MANIFEST_DOMAIN,
                &[command.cat_id.as_str().as_bytes()],
            ),
            &[][..],
        ),
    };
    validate_artifacts(artifacts)?;
    let mut adoptable = 0_u16;
    let mut gc_candidate = 0_u16;
    let mut retained = 0_u16;
    let mut quarantined = 0_u16;
    for artifact in artifacts {
        match artifact {
            ObservedArtifactClassification::AdoptableCatState { .. } => {
                adoptable = adoptable
                    .checked_add(1)
                    .context("retained adoptable artifact count overflows")?
            }
            ObservedArtifactClassification::CatOwnedGcCandidate { .. } => {
                gc_candidate = gc_candidate
                    .checked_add(1)
                    .context("retained GC artifact count overflows")?
            }
            ObservedArtifactClassification::RetainedAuthorityOrData { .. } => {
                retained = retained
                    .checked_add(1)
                    .context("retained authority/data artifact count overflows")?
            }
            ObservedArtifactClassification::QuarantinedForeignOrAmbiguous { .. } => {
                quarantined = quarantined
                    .checked_add(1)
                    .context("retained quarantined artifact count overflows")?
            }
        }
    }
    Ok((
        RetainedEvidence {
            artifact_manifest_digest: manifest_digest,
            adoptable_count: adoptable,
            gc_candidate_count: gc_candidate,
            retained_authority_or_data_count: retained,
            quarantined_count: quarantined,
        },
        post_stop_physical_projection_digest,
    ))
}

fn validate_artifacts(artifacts: &[ObservedArtifactClassification]) -> Result<()> {
    anyhow::ensure!(
        artifacts.len() <= cats_api::runtime_lifecycle::LIFECYCLE_MAX_ARTIFACT_CLASSIFICATIONS
            && artifacts
                .windows(2)
                .all(|pair| pair[0].artifact_id() < pair[1].artifact_id()),
        "post-strong-Stop Cat artifacts are not a bounded sorted unique set"
    );
    Ok(())
}

fn predecessor_runtime_incarnation(response: &LifecycleCommandResponse) -> Option<RandomId128> {
    match &response.result {
        NodeResult::RuntimeReady(ready) => Some(ready.runtime_incarnation.clone()),
        NodeResult::Suspended(suspended) => Some(suspended.runtime_incarnation.clone()),
        NodeResult::SuspendDeclined(declined) => {
            Some(declined.effective_runtime_ready.runtime_incarnation.clone())
        }
        NodeResult::Warm(warm) => Some(warm.source_runtime_incarnation.clone()),
        NodeResult::Killed(killed) => killed.stopped_runtime_incarnation.clone(),
        NodeResult::StartFailed(_)
        | NodeResult::SuspendFailed(_)
        | NodeResult::WarmFailed(_)
        | NodeResult::Cold(_)
        | NodeResult::Deleted(_)
        | NodeResult::NeedsIntervention(_) => None,
    }
}

fn restart_source_postcondition_digest(
    command: &LifecycleCommandEnvelope,
    journal_content_digest: &Sha256Digest,
    cleanup_receipt_digest: Option<&Sha256Digest>,
    same_scan_absence_receipt_digest: &Sha256Digest,
) -> Sha256Digest {
    let command_kind = match command.command_kind() {
        cats_api::runtime_lifecycle::LifecycleCommandKind::Start => b"start".as_slice(),
        cats_api::runtime_lifecycle::LifecycleCommandKind::Suspend => b"suspend".as_slice(),
        cats_api::runtime_lifecycle::LifecycleCommandKind::Warm => b"warm".as_slice(),
        cats_api::runtime_lifecycle::LifecycleCommandKind::Cold => b"cold".as_slice(),
        cats_api::runtime_lifecycle::LifecycleCommandKind::Stop => b"stop".as_slice(),
        cats_api::runtime_lifecycle::LifecycleCommandKind::Delete => b"delete".as_slice(),
    };
    let cleanup_presence = if cleanup_receipt_digest.is_some() {
        b"some".as_slice()
    } else {
        b"none".as_slice()
    };
    let cleanup_digest: &[u8] = cleanup_receipt_digest
        .map(|digest| &digest.as_bytes()[..])
        .unwrap_or(&[]);
    digest_parts(
        RESTART_SOURCE_POSTCONDITION_DOMAIN,
        &[
            command_kind,
            command.operation_id.as_str().as_bytes(),
            command.request_fingerprint.as_bytes(),
            command.cat_id.as_str().as_bytes(),
            command.node_id.as_str().as_bytes(),
            command.placement_identity.node_id.as_str().as_bytes(),
            &command
                .placement_identity
                .placement_epoch
                .get()
                .to_be_bytes(),
            command.runtime_config.config_id.as_str().as_bytes(),
            command.runtime_config.config_digest.as_bytes(),
            journal_content_digest.as_bytes(),
            cleanup_presence,
            cleanup_digest,
            same_scan_absence_receipt_digest.as_bytes(),
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    use cats_api::runtime_inventory::{
        ObservedCatRuntimeTelemetry, ObservedRuntimeCondition, ObservedVolumeWatermarkSummary,
    };
    use cats_api::runtime_lifecycle::{
        DiskRole, ImmutableRuntimeConfig, LifecyclePredecessor, RuntimeNetworkConfig,
        RuntimeVolumeAuthorityInput, RuntimeVolumeConfig, RuntimeVolumeGuestBinding, StartSource,
        StartSpec, StartVolumeAuthority,
    };
    use cats_api::runtime_lifecycle_volume::{
        LifecycleCommandStartVolumeGrantReceipt, LifecycleStartVolumeGrantAuthority,
        LifecycleVolumeCommandScope as WireLifecycleVolumeCommandScope,
    };
    use cats_api::runtime_reconciliation::{
        AcquireOrigin, AsciiText, ContractVersion, Durability, Epoch, FenceEpoch, Generation,
        HostPath, Ipv4Address, MacAddress, NormalAcquireRequest, NormalAcquireResult, RemoteHead,
        UnixMillis, WireU64,
    };

    use super::super::start::InstalledRuntimeProgressVolumeManifest;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn random(byte: u8) -> RandomId128 {
        RandomId128::new(format!("{byte:02x}").repeat(16)).unwrap()
    }

    fn command() -> LifecycleCommandEnvelope {
        let placement = cats_api::runtime_lifecycle::PlacementIdentity {
            node_id: id("node_authority_only"),
            placement_epoch: Epoch::new(1).unwrap(),
        };
        let runtime_config = ImmutableRuntimeConfig::new(
            id("config_authority_only"),
            digest(1),
            2,
            512 * 1024 * 1024,
            digest(2),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("network_authority_only"),
                guest_mac: MacAddress::new("02:00:00:00:00:41").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
            },
            vec![RuntimeVolumeConfig {
                volume_id: id("volume_authority_only"),
                disk_id: id("disk_authority_only"),
                disk_role: DiskRole::Root,
                size_bytes: 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("authority_root"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
        )
        .unwrap();
        LifecycleCommandEnvelope::new(
            id("operation_authority_only"),
            id("workspace_authority_only"),
            id("cat_authority_only"),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config,
            None,
            LifecyclePredecessor::Genesis {
                cat_creation_id: id("creation_authority_only"),
                target_placement: placement,
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: vec![StartVolumeAuthority {
                    volume_id: id("volume_authority_only"),
                    disk_id: id("disk_authority_only"),
                    authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                        expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
                        transition_id: random(3),
                    },
                }],
                source: StartSource::Genesis,
                effect_deadline_unix_ms: UnixMillis::new(9_000_000).unwrap(),
            })),
        )
        .unwrap()
    }

    fn authority_only_fixture(
        lineage_path: &Path,
    ) -> (
        LifecycleCommandEnvelope,
        AtomicStartVolumeGrant,
        InstalledRuntimeProgressManifest,
        StartupPhysicalInventory,
    ) {
        let command = command();
        let configured = command.runtime_config.volumes[0].clone();
        let attachment_id = id("attachment_authority_only");
        let attachment_epoch = FenceEpoch::new(1).unwrap();
        let transition_id = random(3);
        let head = RemoteHead {
            generation: Generation::new(4).unwrap(),
            root_hash: None,
            root_object_id: None,
        };
        let expires = UnixMillis::new(10_000_000).unwrap();
        let authority_receipt = LifecycleCommandStartVolumeGrantReceipt {
            scope: WireLifecycleVolumeCommandScope {
                operation_id: command.operation_id.clone(),
                request_fingerprint: command.request_fingerprint.clone(),
                cat_id: command.cat_id.clone(),
                node_id: command.node_id.clone(),
                placement_identity: command.placement_identity.clone(),
            },
            grant_sequence: WireU64::new(0).unwrap(),
            volume: configured.clone(),
            authority: LifecycleStartVolumeGrantAuthority::NormalAcquire {
                request: NormalAcquireRequest {
                    volume_id: configured.volume_id.clone(),
                    transition_id: transition_id.clone(),
                    attachment_id: attachment_id.clone(),
                    expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
                    placement_epoch: command.placement_identity.placement_epoch,
                    lease_duration_ms: 60_000,
                },
                result: NormalAcquireResult {
                    volume_id: configured.volume_id.clone(),
                    transition_id: transition_id.clone(),
                    attachment_id: attachment_id.clone(),
                    resulting_epoch: attachment_epoch,
                    resulting_head: head.clone(),
                    lease_expires_at: expires,
                },
            },
        };
        let grant_digest = digest(10);
        let grant = AtomicStartVolumeGrant::new(
            VolumeTerminalReceipt {
                volume_id: configured.volume_id.clone(),
                disk_id: configured.disk_id.clone(),
                disk_role: configured.disk_role,
                attachment_id: attachment_id.clone(),
                attachment_epoch,
                local_durable_generation: head.generation,
                remote_durable_generation: head.generation,
                authority_receipt_digest: Some(grant_digest.clone()),
            },
            AcquireOrigin::Normal {
                transition_id: transition_id.clone(),
            },
            head.clone(),
            expires,
            grant_digest.clone(),
            authority_receipt,
            HostPath::new(lineage_path.to_str().unwrap()).unwrap(),
        );
        let authority_artifact = ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: id("artifact_authority_grant"),
            evidence_digest: digest(11),
        };
        let progress = InstalledRuntimeProgressManifest {
            version: ContractVersion::V1,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            placement_identity: command.placement_identity.clone(),
            source_lifecycle_operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            runtime_incarnation: random(12),
            vmm: None,
            network: None,
            volumes: vec![InstalledRuntimeProgressVolumeManifest {
                volume_id: configured.volume_id.clone(),
                disk_id: configured.disk_id.clone(),
                disk_role: configured.disk_role,
                attachment_id: attachment_id.clone(),
                attachment_epoch,
                acquire_origin: AcquireOrigin::Normal { transition_id },
                authority_head: head,
                authority_receipt_digest: Some(grant_digest),
                local_lineage_data_directory: None,
                blockd: None,
                blockd_control_socket_path: None,
                frontend: None,
            }],
            artifact_classifications: vec![authority_artifact.clone()],
            manifest_digest: digest(13),
        };
        let mut artifacts = vec![authority_artifact];
        artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: super::super::artifact_id(
                "atomic-start-progress",
                command.cat_id.as_str().as_bytes(),
            )
            .unwrap(),
            evidence_digest: progress.manifest_digest.clone(),
        });
        artifacts.sort_by(|left, right| left.artifact_id().cmp(right.artifact_id()));
        let cat_manifest = digest(14);
        let physical = StartupPhysicalInventory::Complete {
            scan_id: random(15),
            collected_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            cats: vec![ObservedCatRuntimeTelemetry {
                cat_id: command.cat_id.clone(),
                observed_placement: command.placement_identity.clone(),
                observed_command_journal: None,
                observed_physical_state: ObservedRuntimePhysicalState::StoppedRetained,
                observed_runtime_incarnation: None,
                observed_artifact_manifest_digest: cat_manifest.clone(),
                observed_artifact_classifications: artifacts,
                observed_volumes: vec![ObservedVolumeWatermarkSummary {
                    volume_id: configured.volume_id,
                    disk_id: configured.disk_id,
                    disk_role: configured.disk_role,
                    observed_attachment: ObservedVolumeAttachment::Owned {
                        owner_node_id: command.node_id.clone(),
                        attachment_id,
                        attachment_epoch,
                    },
                    observed_watermark: ObservedVolumeWatermark::Unknown {
                        evidence_digest: digest(16),
                    },
                }],
                observed_conditions: vec![ObservedRuntimeCondition {
                    kind: ObservedRuntimeConditionKind::Progressing,
                    evidence_digest: cat_manifest,
                }],
            }],
            unattributed_artifacts: Vec::new(),
        };
        (command, grant, progress, physical)
    }

    fn mixed_command() -> LifecycleCommandEnvelope {
        let placement = cats_api::runtime_lifecycle::PlacementIdentity {
            node_id: id("node_mixed"),
            placement_epoch: Epoch::new(2).unwrap(),
        };
        let volumes = vec![
            RuntimeVolumeConfig {
                volume_id: id("volume_a_root"),
                disk_id: id("disk_a_root"),
                disk_role: DiskRole::Root,
                size_bytes: 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("mixed_root"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            },
            RuntimeVolumeConfig {
                volume_id: id("volume_b_data"),
                disk_id: id("disk_b_data"),
                disk_role: DiskRole::Persistent,
                size_bytes: 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("mixed_data"),
                guest_device_slot: 1,
                guest_binding: RuntimeVolumeGuestBinding::PersistentExt4 {
                    filesystem_uuid: random(22),
                    mount_path: AsciiText::new("/data").unwrap(),
                },
            },
        ];
        let runtime_config = ImmutableRuntimeConfig::new(
            id("config_mixed"),
            digest(20),
            2,
            512 * 1024 * 1024,
            digest(21),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("network_mixed"),
                guest_mac: MacAddress::new("02:00:00:00:00:42").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.6").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.5").unwrap(),
            },
            volumes.clone(),
        )
        .unwrap();
        let authorities = volumes
            .iter()
            .enumerate()
            .map(|(index, volume)| StartVolumeAuthority {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                    expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
                    transition_id: random(23 + u8::try_from(index).unwrap()),
                },
            })
            .collect();
        LifecycleCommandEnvelope::new(
            id("operation_mixed"),
            id("workspace_mixed"),
            id("cat_mixed"),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config,
            None,
            LifecyclePredecessor::Genesis {
                cat_creation_id: id("creation_mixed"),
                target_placement: placement,
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: authorities,
                source: StartSource::Genesis,
                effect_deadline_unix_ms: UnixMillis::new(9_000_000).unwrap(),
            })),
        )
        .unwrap()
    }

    fn mixed_grant(
        command: &LifecycleCommandEnvelope,
        index: usize,
        lineage_path: &Path,
    ) -> AtomicStartVolumeGrant {
        let configured = command.runtime_config.volumes[index].clone();
        let byte = 23 + u8::try_from(index).unwrap();
        let transition_id = random(byte);
        let attachment_id = Id::new(format!("attachment_mixed_{index}")).unwrap();
        let attachment_epoch = FenceEpoch::new(1 + u64::try_from(index).unwrap()).unwrap();
        let head = RemoteHead {
            generation: Generation::new(4 + u64::try_from(index).unwrap()).unwrap(),
            root_hash: None,
            root_object_id: None,
        };
        let expires = UnixMillis::new(10_000_000).unwrap();
        let grant_digest = digest(30 + u8::try_from(index).unwrap());
        let authority_receipt = LifecycleCommandStartVolumeGrantReceipt {
            scope: WireLifecycleVolumeCommandScope {
                operation_id: command.operation_id.clone(),
                request_fingerprint: command.request_fingerprint.clone(),
                cat_id: command.cat_id.clone(),
                node_id: command.node_id.clone(),
                placement_identity: command.placement_identity.clone(),
            },
            grant_sequence: WireU64::new(0).unwrap(),
            volume: configured.clone(),
            authority: LifecycleStartVolumeGrantAuthority::NormalAcquire {
                request: NormalAcquireRequest {
                    volume_id: configured.volume_id.clone(),
                    transition_id: transition_id.clone(),
                    attachment_id: attachment_id.clone(),
                    expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
                    placement_epoch: command.placement_identity.placement_epoch,
                    lease_duration_ms: 60_000,
                },
                result: NormalAcquireResult {
                    volume_id: configured.volume_id.clone(),
                    transition_id: transition_id.clone(),
                    attachment_id: attachment_id.clone(),
                    resulting_epoch: attachment_epoch,
                    resulting_head: head.clone(),
                    lease_expires_at: expires,
                },
            },
        };
        AtomicStartVolumeGrant::new(
            VolumeTerminalReceipt {
                volume_id: configured.volume_id,
                disk_id: configured.disk_id,
                disk_role: configured.disk_role,
                attachment_id,
                attachment_epoch,
                local_durable_generation: head.generation,
                remote_durable_generation: head.generation,
                authority_receipt_digest: Some(grant_digest.clone()),
            },
            AcquireOrigin::Normal { transition_id },
            head,
            expires,
            grant_digest,
            authority_receipt,
            HostPath::new(lineage_path.to_str().unwrap()).unwrap(),
        )
    }

    fn mixed_projection_fixture(
        materialized_path: &Path,
        absent_path: &Path,
    ) -> (
        LifecycleCommandEnvelope,
        Vec<AtomicStartVolumeGrant>,
        InstalledRuntimeProgressManifest,
        StartupPhysicalInventory,
    ) {
        let command = mixed_command();
        let grants = vec![
            mixed_grant(&command, 0, materialized_path),
            mixed_grant(&command, 1, absent_path),
        ];
        let volumes = grants
            .iter()
            .enumerate()
            .map(|(index, grant)| InstalledRuntimeProgressVolumeManifest {
                volume_id: grant.volume.volume_id.clone(),
                disk_id: grant.volume.disk_id.clone(),
                disk_role: grant.volume.disk_role,
                attachment_id: grant.volume.attachment_id.clone(),
                attachment_epoch: grant.volume.attachment_epoch,
                acquire_origin: grant.acquire_origin.clone(),
                authority_head: grant.authoritative_head.clone(),
                authority_receipt_digest: Some(grant.grant_receipt_digest.clone()),
                local_lineage_data_directory: (index == 0)
                    .then(|| grant.planned_local_lineage_data_directory.clone()),
                blockd: None,
                blockd_control_socket_path: None,
                frontend: None,
            })
            .collect();
        let artifacts = grants
            .iter()
            .enumerate()
            .map(
                |(index, _)| ObservedArtifactClassification::RetainedAuthorityOrData {
                    artifact_id: Id::new(format!("artifact_mixed_grant_{index}")).unwrap(),
                    evidence_digest: digest(40 + u8::try_from(index).unwrap()),
                },
            )
            .collect::<Vec<_>>();
        let progress = InstalledRuntimeProgressManifest::new(
            &command,
            random(42),
            None,
            None,
            volumes,
            artifacts.clone(),
        )
        .unwrap();
        let mut projected_artifacts = artifacts;
        projected_artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: super::super::artifact_id(
                "atomic-start-progress",
                command.cat_id.as_str().as_bytes(),
            )
            .unwrap(),
            evidence_digest: progress.manifest_digest.clone(),
        });
        projected_artifacts.sort_by(|left, right| left.artifact_id().cmp(right.artifact_id()));
        let cat_manifest = digest(43);
        let observed_volumes = grants
            .iter()
            .enumerate()
            .map(|(index, grant)| ObservedVolumeWatermarkSummary {
                volume_id: grant.volume.volume_id.clone(),
                disk_id: grant.volume.disk_id.clone(),
                disk_role: grant.volume.disk_role,
                observed_attachment: ObservedVolumeAttachment::Owned {
                    owner_node_id: command.node_id.clone(),
                    attachment_id: grant.volume.attachment_id.clone(),
                    attachment_epoch: grant.volume.attachment_epoch,
                },
                observed_watermark: ObservedVolumeWatermark::Unknown {
                    evidence_digest: digest(44 + u8::try_from(index).unwrap()),
                },
            })
            .collect();
        let physical = StartupPhysicalInventory::Complete {
            scan_id: random(46),
            collected_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            cats: vec![ObservedCatRuntimeTelemetry {
                cat_id: command.cat_id.clone(),
                observed_placement: command.placement_identity.clone(),
                observed_command_journal: None,
                observed_physical_state: ObservedRuntimePhysicalState::StoppedRetained,
                observed_runtime_incarnation: None,
                observed_artifact_manifest_digest: cat_manifest.clone(),
                observed_artifact_classifications: projected_artifacts,
                observed_volumes,
                observed_conditions: vec![ObservedRuntimeCondition {
                    kind: ObservedRuntimeConditionKind::Progressing,
                    evidence_digest: cat_manifest,
                }],
            }],
            unattributed_artifacts: Vec::new(),
        };
        (command, grants, progress, physical)
    }

    #[test]
    fn restart_source_postcondition_binds_cleanup_scan_and_journal_replay() {
        let command = command();
        let journal = digest(40);
        let cleanup = digest(41);
        let scan = digest(42);
        let sealed = restart_source_postcondition_digest(&command, &journal, Some(&cleanup), &scan);
        assert_eq!(
            restart_source_postcondition_digest(&command, &journal, Some(&cleanup), &scan,),
            sealed,
            "crash replay of the exact cleanup and same-scan proof must be stable"
        );
        assert_ne!(
            restart_source_postcondition_digest(&command, &journal, None, &scan),
            sealed
        );
        assert_ne!(
            restart_source_postcondition_digest(&command, &journal, Some(&digest(43)), &scan,),
            sealed
        );
        assert_ne!(
            restart_source_postcondition_digest(&command, &journal, Some(&cleanup), &digest(44),),
            sealed
        );
        assert_ne!(
            restart_source_postcondition_digest(&command, &digest(45), Some(&cleanup), &scan,),
            sealed
        );
    }

    #[test]
    fn sequence_zero_owned_grant_with_complete_zero_mutation_scan_is_retained() {
        let temporary = tempfile::tempdir().unwrap();
        let lineage = temporary.path().join("not-materialized");
        let (command, grant, progress, physical) = authority_only_fixture(&lineage);
        let state =
            crate::state_directory::StateDirectory::unanchored(temporary.path().to_path_buf());

        validate_unmaterialized_start_post_stop_projection(
            &state,
            &command,
            &[grant],
            &progress,
            None,
            &physical,
        )
        .unwrap();
    }

    #[test]
    fn authority_only_retention_rejects_any_lineage_or_unattributed_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let lineage = temporary.path().join("materialized");
        let (command, grant, progress, mut physical) = authority_only_fixture(&lineage);
        let state =
            crate::state_directory::StateDirectory::unanchored(temporary.path().to_path_buf());
        std::fs::create_dir(&lineage).unwrap();
        assert!(validate_unmaterialized_start_post_stop_projection(
            &state,
            &command,
            std::slice::from_ref(&grant),
            &progress,
            None,
            &physical,
        )
        .is_err());

        std::fs::remove_dir(&lineage).unwrap();
        let StartupPhysicalInventory::Complete {
            unattributed_artifacts,
            ..
        } = &mut physical
        else {
            unreachable!()
        };
        unattributed_artifacts.push(
            ObservedArtifactClassification::QuarantinedForeignOrAmbiguous {
                artifact_id: id("artifact_unknown"),
                evidence_digest: digest(17),
            },
        );
        assert!(validate_unmaterialized_start_post_stop_projection(
            &state,
            &command,
            &[grant],
            &progress,
            None,
            &physical,
        )
        .is_err());
    }

    #[test]
    fn mixed_progress_closes_each_unmaterialized_slot_and_replays_exactly() {
        let temporary = tempfile::tempdir().unwrap();
        let materialized = temporary.path().join("materialized-root");
        let absent = temporary.path().join("absent-persistent");
        std::fs::create_dir(&materialized).unwrap();
        let (command, grants, progress, physical) =
            mixed_projection_fixture(&materialized, &absent);
        let state =
            crate::state_directory::StateDirectory::unanchored(temporary.path().to_path_buf());

        validate_unmaterialized_start_post_stop_projection(
            &state, &command, &grants, &progress, None, &physical,
        )
        .unwrap();
        validate_unmaterialized_start_post_stop_projection(
            &state, &command, &grants, &progress, None, &physical,
        )
        .unwrap();

        let mut head_tampered = progress.clone();
        head_tampered.volumes[1].authority_head.generation =
            Generation::new(grants[1].authoritative_head.generation.get() + 1).unwrap();
        assert!(validate_unmaterialized_start_post_stop_projection(
            &state,
            &command,
            &grants,
            &head_tampered,
            None,
            &physical,
        )
        .is_err());

        std::fs::create_dir(&absent).unwrap();
        assert!(validate_unmaterialized_start_post_stop_projection(
            &state, &command, &grants, &progress, None, &physical,
        )
        .is_err());
    }

    #[test]
    fn unmaterialized_lineage_absence_rejects_an_ancestor_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ancestor = temporary.path().join("lineage-parent");
        std::os::unix::fs::symlink(outside.path(), &ancestor).unwrap();
        let target = HostPath::new(ancestor.join("epoch-1").to_str().unwrap()).unwrap();
        let state =
            crate::state_directory::StateDirectory::unanchored(temporary.path().to_path_buf());

        assert!(ensure_descriptor_relative_path_absent(&state, &target).is_err());
    }
}
