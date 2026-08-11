//! Closed classifiers for retiring process-local Running admission.
//!
//! Current Running admission and superseded route retirement are deliberately
//! separate authorities.  A current phase may prove that a gate is ready to
//! open; this module can only retain an already-live shared-registry cell long
//! enough to close it. Immutable physical-launch provenance (R0) comes from
//! the Desired sealed in every AuthorizedBlockd launch checkpoint. The exact
//! live-gate predecessor (R1) comes from the process-owned registry session,
//! while the Control-plane Desired is the endpoint-only successor (R2). None
//! of those authorities is inferred from mutable public route inventory.

use std::collections::BTreeMap;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    DesiredRuntimeSpec, LifecycleAdmission, ReconcileStep, RequireIdleCheckpoint,
    RuntimeCheckpoint, RuntimeTarget, RuntimeTransition,
};

use super::inventory::{AuthorizedBlockdInventoryEvidence, DesiredCheckpointBinding};
use super::{AdmissionCellObservation, AdmissionSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteRetirementMode {
    EndpointOnly,
    GlobalDesired,
    GlobalPhysicalNegative,
}

/// Binds every copy of the one-shot RequireIdle source tuple. The Desired,
/// CloseAdmission journal token and Armed/Busy/Closed evidence must name the
/// same attempt, source revision and runtime incarnation; no individual copy
/// can stand in for the other two.
pub(super) fn validate_require_idle_checkpoint_tuple(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<()> {
    let RuntimeTransition::RequireIdle {
        attempt_id,
        source_revision,
        source_runtime_incarnation,
    } = &desired.transition
    else {
        anyhow::bail!("Desired is not RequireIdle")
    };
    let ReconcileStep::CloseAdmission {
        require_idle_attempt_id: Some(step_attempt_id),
    } = &checkpoint.step
    else {
        anyhow::bail!("RequireIdle checkpoint lacks its CloseAdmission attempt token")
    };
    let (saved_attempt_id, saved_revision, saved_incarnation) = match &checkpoint.require_idle {
        RequireIdleCheckpoint::Armed {
            attempt_id,
            source_revision,
            source_runtime_incarnation,
        }
        | RequireIdleCheckpoint::Busy {
            attempt_id,
            source_revision,
            source_runtime_incarnation,
            ..
        }
        | RequireIdleCheckpoint::Closed {
            attempt_id,
            source_revision,
            source_runtime_incarnation,
        } => (attempt_id, source_revision, source_runtime_incarnation),
        RequireIdleCheckpoint::NotApplicable => {
            anyhow::bail!("RequireIdle checkpoint lacks one-shot evidence")
        }
    };
    anyhow::ensure!(
        step_attempt_id == attempt_id
            && saved_attempt_id == attempt_id
            && saved_revision == source_revision
            && saved_incarnation == source_runtime_incarnation,
        "RequireIdle Desired, journal and checkpoint evidence name different source tuples"
    );
    Ok(())
}

/// Returns the one sealed Running Desired which authorized every retained
/// blockd in this launch (R0). Mixed or missing launch lineage is unavailable,
/// not permission to infer either the live-gate predecessor or successor from
/// the new Desired.
pub(crate) fn sealed_running_predecessor(
    checkpoint: &RuntimeCheckpoint,
    blockds: Option<
        &BTreeMap<cats_api::runtime_reconciliation::Id, AuthorizedBlockdInventoryEvidence>,
    >,
) -> anyhow::Result<DesiredRuntimeSpec> {
    let blockds = blockds.context("retained Running checkpoint lacks AuthorizedBlockd lineage")?;
    let first = blockds
        .values()
        .next()
        .context("retained Running checkpoint has no AuthorizedBlockd lineage")?;
    let predecessor = first.checkpoint.desired.clone();
    anyhow::ensure!(
        predecessor.target == RuntimeTarget::Running
            && predecessor.cat_id == checkpoint.cat_id
            && predecessor.placement.node_id == checkpoint.node_id
            && predecessor.placement.placement_epoch == checkpoint.placement_epoch
            && predecessor.volumes.len() == blockds.len()
            && blockds.iter().all(|(volume_id, blockd)| {
                blockd.checkpoint.desired == predecessor
                    && &blockd.checkpoint.attachment.identity.volume_id == volume_id
                    && predecessor.volumes.iter().any(|volume| {
                        &volume.volume_id == volume_id && volume == &blockd.checkpoint.volume
                    })
            }),
        "retained Running launch has no single sealed Desired predecessor"
    );
    Ok(predecessor)
}

/// Closed superseded classifier. It never returns EndpointOnly unless the old
/// cell is the exact checkpoint snapshot and every non-Endpoint Desired field
/// is unchanged. Any already-fail-closed cell goes through global removal so
/// no old epoch can be reconstructed.
pub(crate) fn classify_superseded_route_retirement(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    binding: DesiredCheckpointBinding,
    predecessor: Option<&DesiredRuntimeSpec>,
    cell: &AdmissionCellObservation,
) -> anyhow::Result<Option<RouteRetirementMode>> {
    if binding != DesiredCheckpointBinding::Superseded
        || checkpoint.runtime_launch.identity().is_none()
    {
        return Ok(None);
    }
    let checkpoint_cell = AdmissionSnapshot::from_checkpoint(checkpoint)?;
    if let Some(predecessor) = predecessor {
        anyhow::ensure!(
            checkpoint.desired_revision == predecessor.desired_revision
                && checkpoint.spec_digest == predecessor.spec_digest
                && checkpoint.node_id == predecessor.placement.node_id
                && checkpoint.placement_epoch == predecessor.placement.placement_epoch,
            "superseded route retirement does not bind the sealed predecessor"
        );
        if cell.snapshot() == &checkpoint_cell && endpoint_only_successor(predecessor, desired) {
            return Ok(Some(RouteRetirementMode::EndpointOnly));
        }
        let restart_closed = cell.snapshot() == &checkpoint_cell.fail_closed()
            && cell.guards().platform_guards == 0
            && cell.guards().endpoint_guards.is_empty()
            && checkpoint.lifecycle_admission == LifecycleAdmission::Open
            && matches!(
                checkpoint.step,
                ReconcileStep::Stable {
                    state: cats_api::runtime_reconciliation::StableState::Running
                }
            )
            && checkpoint.route_gates.iter().all(|route| {
                route.gate == cats_api::runtime_reconciliation::RouteGateState::Active
            })
            && restart_closed_endpoint_successor(predecessor, desired);
        if restart_closed {
            return Ok(Some(RouteRetirementMode::EndpointOnly));
        }
    }
    anyhow::ensure!(
        cell.snapshot() == &checkpoint_cell || cell.snapshot() == &checkpoint_cell.fail_closed(),
        "superseded route retirement cell is not the exact live predecessor"
    );
    Ok(Some(RouteRetirementMode::GlobalDesired))
}

/// Same-process checkpoint-first continuation for an Endpoint-only successor.
/// The checkpoint already names the current successor, while the live cell may
/// still be either endpoint of the one process-owned effect edge. This never
/// authorizes a new edge: the caller must prove the exact stored edge for a
/// non-identical cell and the effect rechecks it before mutation.
pub(crate) fn classify_current_endpoint_route_retirement(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    binding: DesiredCheckpointBinding,
    predecessor: Option<&DesiredRuntimeSpec>,
    cell: &AdmissionCellObservation,
    stored_edge_allows_live: bool,
) -> anyhow::Result<Option<RouteRetirementMode>> {
    let Some(predecessor) = predecessor else {
        return Ok(None);
    };
    if binding != DesiredCheckpointBinding::Current
        || checkpoint.runtime_launch.identity().is_none()
        || !endpoint_only_successor(predecessor, desired)
        || !matches!(
            checkpoint.step,
            ReconcileStep::CloseGate { .. } | ReconcileStep::InstallGate { .. }
        )
    {
        return Ok(None);
    }
    anyhow::ensure!(
        checkpoint.cat_id == desired.cat_id
            && checkpoint.node_id == desired.placement.node_id
            && checkpoint.placement_epoch == desired.placement.placement_epoch
            && checkpoint.desired_revision == desired.desired_revision
            && checkpoint.spec_digest == desired.spec_digest,
        "current Endpoint retirement checkpoint does not bind its successor Desired"
    );
    let checkpoint_cell = AdmissionSnapshot::from_checkpoint(checkpoint)?;
    anyhow::ensure!(
        cell.snapshot() == &checkpoint_cell || stored_edge_allows_live,
        "current Endpoint retirement lacks its exact checkpoint cell or stored effect edge"
    );
    Ok(Some(RouteRetirementMode::EndpointOnly))
}

/// Current global-close continuation. This is intentionally disjoint from the
/// current Running-tail phase classifier: it accepts only a durable global
/// close/RequireIdle journal (or a non-Running Desired still backed by the
/// sealed Running launch) and can never authorize an open/install edge.
pub(crate) fn classify_current_global_route_retirement(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    binding: DesiredCheckpointBinding,
    cell: &AdmissionCellObservation,
) -> anyhow::Result<Option<RouteRetirementMode>> {
    if binding != DesiredCheckpointBinding::Current
        || checkpoint.runtime_launch.identity().is_none()
        || (desired.target == RuntimeTarget::Running
            && !matches!(checkpoint.step, ReconcileStep::CloseAdmission { .. }))
    {
        return Ok(None);
    }
    if matches!(desired.transition, RuntimeTransition::RequireIdle { .. }) {
        validate_require_idle_checkpoint_tuple(desired, checkpoint)?;
    }
    let checkpoint_cell = AdmissionSnapshot::from_checkpoint(checkpoint)?;
    let exact_current = cell.snapshot() == &checkpoint_cell;
    let exact_source_busy = matches!(
        &checkpoint.require_idle,
        RequireIdleCheckpoint::Busy {
            source_revision,
            source_runtime_incarnation,
            gate_closed: false,
            ..
        } if cell.snapshot().applied_desired_revision() == *source_revision
            && cell.snapshot().runtime_incarnation() == Some(source_runtime_incarnation)
            && cell.snapshot().placement() == &desired.placement
            && cell.snapshot().lifecycle_admission() == LifecycleAdmission::Open
            && cell.snapshot().endpoints() == checkpoint.route_gates
    );
    anyhow::ensure!(
        exact_current || exact_source_busy,
        "current route-retirement journal does not match its live cell"
    );
    Ok(Some(RouteRetirementMode::GlobalDesired))
}

pub(super) fn endpoint_only_successor(old: &DesiredRuntimeSpec, new: &DesiredRuntimeSpec) -> bool {
    old.version == new.version
        && old.workspace_id == new.workspace_id
        && old.cat_id == new.cat_id
        && old.desired_revision < new.desired_revision
        && old.target == RuntimeTarget::Running
        && new.target == RuntimeTarget::Running
        && old.placement == new.placement
        && old.runtime == new.runtime
        && old.volumes == new.volumes
        && old.endpoints != new.endpoints
        && matches!(old.transition, RuntimeTransition::CancelAndDrain)
        && matches!(new.transition, RuntimeTransition::CancelAndDrain)
        && old.spec_digest != new.spec_digest
}

/// A process restart burns every formerly Active route epoch when the
/// registry reconstructs its cell Closed. Reopening is possible only from a
/// strict Endpoint-only successor that removes an old Endpoint or replaces
/// every retained old binding with a strictly higher epoch; an unchanged old
/// binding must remain permanently closed.
pub(super) fn restart_closed_endpoint_successor(
    predecessor: &DesiredRuntimeSpec,
    successor: &DesiredRuntimeSpec,
) -> bool {
    super::authorized_blockd::validate_running_endpoint_only_desired_successor(
        predecessor,
        successor,
    )
    .is_ok()
        && predecessor.endpoints.iter().all(|old| {
            successor
                .endpoints
                .iter()
                .find(|current| current.endpoint_id == old.endpoint_id)
                .is_none_or(|current| current != old && current.route_epoch > old.route_epoch)
        })
}
