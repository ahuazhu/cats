use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, encode_runtime_checkpoint, AppliedDesiredEvidence, AssignedKind,
    AssignedPlacement, CheckpointRouteGate, ContractError, ContractErrorDetail, ContractVersion,
    DesiredRuntimeSpec, EndpointGuardCount, EndpointIntent, Id, LifecycleAdmission, RandomId128,
    ReconcileStep, RequireIdleCheckpoint, Revision, RouteGateBinding, RouteGateState,
    RuntimeCheckpoint, RuntimeTarget, RuntimeTransition, UnixMillis,
};
use thiserror::Error;

use super::admission_port::{
    AdmissionGatePort, AdmissionSnapshot, GatePortError, IdleCloseResult, SnapshotError,
};
use super::checkpoint::{CheckpointStoreError, FileCheckpointStore, StoredCheckpoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistTimes {
    pub before_effect: UnixMillis,
    pub after_effect: UnixMillis,
}

#[derive(Debug)]
pub enum GateTransitionResult {
    Installed {
        checkpoint: StoredCheckpoint,
    },
    Closed {
        checkpoint: StoredCheckpoint,
    },
    RequireIdleBusy {
        checkpoint: StoredCheckpoint,
        gate_closed: bool,
        /// A local port error is retained for diagnostics. The port contract
        /// guarantees that an error is fail-closed; the durable Busy outcome
        /// is therefore still authoritative for this one attempt.
        port_error: Option<GatePortError>,
    },
    RequireIdleClosed {
        checkpoint: StoredCheckpoint,
    },
}

impl GateTransitionResult {
    pub fn checkpoint(&self) -> &StoredCheckpoint {
        match self {
            Self::Installed { checkpoint }
            | Self::Closed { checkpoint }
            | Self::RequireIdleBusy { checkpoint, .. }
            | Self::RequireIdleClosed { checkpoint } => checkpoint,
        }
    }
}

#[derive(Debug, Error)]
pub enum AppliedDesiredError {
    #[error("current DesiredRuntimeSpec is not a valid shared contract: {0}")]
    DesiredContract(#[from] ContractError),
    #[error("RuntimeCheckpoint is not a valid shared contract: {error}")]
    CheckpointContract { error: ContractError },
    #[error("checkpoint Cat {checkpoint_cat} does not match Desired Cat {desired_cat}")]
    WrongCat { checkpoint_cat: Id, desired_cat: Id },
    #[error("checkpoint and current Desired disagree on revision")]
    Revision { error: ContractError },
    #[error("checkpoint and current Desired disagree on spec digest")]
    SpecDigest { error: ContractError },
    #[error("checkpoint and current Desired disagree on placement")]
    Placement { error: ContractError },
    #[error("checkpoint route identity is inconsistent: {0}")]
    RouteIdentity(#[from] SnapshotError),
    #[error("checkpoint route {endpoint_id} belongs to another workspace")]
    RouteWorkspace { endpoint_id: Id },
    #[error("active checkpoint route {endpoint_id} is absent from current Desired")]
    ActiveRouteMissing { endpoint_id: Id },
    #[error("active checkpoint route {endpoint_id} does not match current Desired")]
    ActiveRouteBinding { endpoint_id: Id },
    #[error("RequireIdle source runtime incarnation does not match the checkpoint")]
    RuntimeIncarnation,
}

#[derive(Debug, Error)]
pub enum GateReconcileError {
    #[error(transparent)]
    Checkpoint(#[from] CheckpointStoreError),
    #[error(transparent)]
    AppliedDesired(#[from] AppliedDesiredError),
    #[error("after-effect checkpoint time precedes before-effect time")]
    TimestampRegression,
    #[error("Desired revision {presented:?} is older than checkpoint revision {current:?}")]
    StaleDesired {
        presented: Revision,
        current: Revision,
    },
    #[error("new Desired belongs to another Cat")]
    WrongCat,
    #[error("new Desired conflicts with the checkpoint route workspace")]
    WrongWorkspace,
    #[error("new Desired placement belongs to another Node")]
    WrongNode,
    #[error("new Desired placement epoch regressed")]
    PlacementEpochRegression,
    #[error("RequireIdle must be evaluated from its exact Running source checkpoint")]
    WrongRequireIdleSource,
    #[error("this transition requires a non-RequireIdle Desired")]
    UnexpectedRequireIdle,
    #[error("gate installation requires a Running Desired and runtime incarnation")]
    RuntimeNotInstallable,
    #[error("Desired does not contain Endpoint {0}")]
    EndpointNotFound(Id),
    #[error("Endpoint {0} route epoch regressed")]
    RouteEpochRegression(Id),
    #[error("Endpoint {0} reused an epoch for a different binding")]
    RouteBindingConflict(Id),
    #[error("Endpoint {0} attempted to reopen a closed route epoch")]
    ClosedEpochReuse(Id),
    #[error("Endpoint {0} must be closed before installing a higher route epoch")]
    GateMustBeClosed(Id),
    #[error("admission checkpoint contains an invalid route identity: {0}")]
    Snapshot(#[from] SnapshotError),
    #[error("AdmissionGatePort failed after the checkpoint was durable: {0}")]
    Port(#[from] GatePortError),
    #[error("checkpoint does not hold the expected RequireIdle state")]
    WrongRequireIdleCheckpoint,
    #[error("post-close Busy can only be recorded while every gate is closed")]
    GateNotClosed,
    #[error(
        "the live AdmissionCell is not the open source of the durable RequireIdle Busy result"
    )]
    WrongOpenBusySource,
    #[error("active Endpoint {0} must be closed before applying its changed or removed binding")]
    ActiveRouteChanged(Id),
    #[error("active gates cannot survive a placement epoch change")]
    ActiveGatesAcrossPlacement,
}

/// Constructs observation evidence only after the complete checkpoint and the
/// complete current Desired agree on revision, digest, placement, and runtime
/// identity. No field is recovered from `stable_state` or `step`.
pub fn applied_desired_evidence(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
) -> Result<AppliedDesiredEvidence, AppliedDesiredError> {
    // This validates the full Desired and its self-digest. A caller cannot
    // construct authority by handing this boundary an unchecked Rust value.
    encode_desired_runtime_spec(desired)?;
    encode_runtime_checkpoint(checkpoint)
        .map_err(|error| AppliedDesiredError::CheckpointContract { error })?;
    if checkpoint.cat_id != desired.cat_id {
        return Err(AppliedDesiredError::WrongCat {
            checkpoint_cat: checkpoint.cat_id.clone(),
            desired_cat: desired.cat_id.clone(),
        });
    }
    if checkpoint.desired_revision != desired.desired_revision {
        let error = if checkpoint.desired_revision < desired.desired_revision {
            contract_error(
                ContractErrorDetail::StaleRevision {
                    cat_id: desired.cat_id.clone(),
                    presented_revision: checkpoint.desired_revision,
                    current_revision: desired.desired_revision,
                },
                "checkpoint revision is stale",
            )
        } else {
            contract_error(
                ContractErrorDetail::WrongRevision {
                    cat_id: desired.cat_id.clone(),
                    expected_revision: desired.desired_revision,
                    presented_revision: checkpoint.desired_revision,
                },
                "checkpoint revision is not current",
            )
        };
        return Err(AppliedDesiredError::Revision { error });
    }
    if checkpoint.spec_digest != desired.spec_digest {
        return Err(AppliedDesiredError::SpecDigest {
            error: contract_error(
                ContractErrorDetail::RevisionDigestConflict {
                    cat_id: desired.cat_id.clone(),
                    desired_revision: desired.desired_revision,
                    expected_digest: desired.spec_digest.clone(),
                    presented_digest: checkpoint.spec_digest.clone(),
                },
                "checkpoint spec digest differs from current Desired",
            ),
        });
    }
    let presented_placement = checkpoint_placement(checkpoint);
    if presented_placement != desired.placement {
        return Err(AppliedDesiredError::Placement {
            error: contract_error(
                ContractErrorDetail::WrongPlacement {
                    cat_id: desired.cat_id.clone(),
                    desired_revision: desired.desired_revision,
                    expected: desired.placement.clone(),
                    presented: presented_placement,
                },
                "checkpoint placement differs from current Desired",
            ),
        });
    }
    AdmissionSnapshot::from_checkpoint(checkpoint)?;
    validate_routes_against_desired(checkpoint, desired)?;
    if let RuntimeTransition::RequireIdle {
        source_runtime_incarnation,
        ..
    } = &desired.transition
    {
        if checkpoint.runtime_incarnation.as_ref() != Some(source_runtime_incarnation) {
            return Err(AppliedDesiredError::RuntimeIncarnation);
        }
    }
    Ok(AppliedDesiredEvidence {
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        target: desired.target,
    })
}

/// Specific checkpoint-first sequencing over the narrow admission port.
pub struct GateSequencer<'a, P: AdmissionGatePort> {
    store: &'a FileCheckpointStore,
    port: &'a mut P,
}

impl<'a, P: AdmissionGatePort> GateSequencer<'a, P> {
    pub fn new(store: &'a FileCheckpointStore, port: &'a mut P) -> Self {
        Self { store, port }
    }

    /// Installs or advances one Endpoint gate after the caller has verified
    /// that the complete Running Desired is platform-ready. This gate-only
    /// spine does not infer readiness from a lifecycle step. The durable
    /// checkpoint is published before the AdmissionCell can become Active.
    pub fn install_gate(
        &mut self,
        current: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
        endpoint_id: &Id,
        times: PersistTimes,
    ) -> Result<GateTransitionResult, GateReconcileError> {
        validate_times(times)?;
        if desired.target != RuntimeTarget::Running {
            return Err(GateReconcileError::RuntimeNotInstallable);
        }
        let expected_snapshot = self.expected_transition_snapshot(current, desired)?;
        let mut staged = stage_desired(current.checkpoint(), desired, times.before_effect)?;
        if desired.placement.placement_epoch != current.checkpoint().placement_epoch
            && current
                .checkpoint()
                .route_gates
                .iter()
                .any(|route| route.gate == RouteGateState::Active)
        {
            return Err(GateReconcileError::ActiveGatesAcrossPlacement);
        }
        let incarnation = staged
            .runtime_incarnation
            .clone()
            .ok_or(GateReconcileError::RuntimeNotInstallable)?;
        let endpoint = desired
            .endpoints
            .iter()
            .find(|endpoint| &endpoint.endpoint_id == endpoint_id)
            .ok_or_else(|| GateReconcileError::EndpointNotFound(endpoint_id.clone()))?;
        let binding = RouteGateBinding {
            workspace_id: desired.workspace_id.clone(),
            endpoint_id: endpoint.endpoint_id.clone(),
            hostname: endpoint.hostname.clone(),
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            runtime_incarnation: incarnation,
            route_epoch: endpoint.route_epoch,
            protocol: endpoint.protocol,
            target_port: endpoint.target_port,
        };
        validate_unchanged_active_routes(&staged, desired, Some(endpoint_id))?;
        install_route_in_checkpoint(&mut staged, binding)?;
        staged.lifecycle_admission = LifecycleAdmission::Open;
        staged.step = ReconcileStep::InstallGate {
            endpoint_id: endpoint_id.clone(),
            route_epoch: endpoint.route_epoch,
        };
        let replacement_snapshot = AdmissionSnapshot::from_checkpoint(&staged)?;
        let staged = self.store.replace(current, &staged)?;
        self.port
            .install_gate(&expected_snapshot, &replacement_snapshot, endpoint_id)?;

        let mut completed = staged.checkpoint().clone();
        completed.updated_at_unix_ms = times.after_effect;
        let completed = self.store.replace(&staged, &completed)?;
        Ok(GateTransitionResult::Installed {
            checkpoint: completed,
        })
    }

    /// Closes all work admission for an ordinary transition. RequireIdle must
    /// use [`Self::begin_require_idle`] so Busy can leave the cell unchanged.
    pub fn close_all(
        &mut self,
        current: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
        times: PersistTimes,
    ) -> Result<GateTransitionResult, GateReconcileError> {
        validate_times(times)?;
        if matches!(desired.transition, RuntimeTransition::RequireIdle { .. }) {
            return Err(GateReconcileError::UnexpectedRequireIdle);
        }
        let expected_snapshot = self.expected_transition_snapshot(current, desired)?;
        let mut staged = stage_desired(current.checkpoint(), desired, times.before_effect)?;
        close_checkpoint_gates(&mut staged);
        staged.step = ReconcileStep::CloseAdmission {
            require_idle_attempt_id: None,
        };
        staged.require_idle = RequireIdleCheckpoint::NotApplicable;
        let replacement_snapshot = AdmissionSnapshot::from_checkpoint(&staged)?;
        let staged = self.store.replace(current, &staged)?;
        self.port
            .close_all(&expected_snapshot, &replacement_snapshot)?;

        let mut completed = staged.checkpoint().clone();
        completed.updated_at_unix_ms = times.after_effect;
        let completed = self.store.replace(&staged, &completed)?;
        Ok(GateTransitionResult::Closed {
            checkpoint: completed,
        })
    }

    /// Arms and evaluates one RequireIdle attempt exactly once.
    pub fn begin_require_idle(
        &mut self,
        source: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
        times: PersistTimes,
    ) -> Result<GateTransitionResult, GateReconcileError> {
        validate_times(times)?;
        let (attempt_id, source_revision, source_incarnation) = require_idle_fields(desired)?;
        if desired.desired_revision <= source.checkpoint().desired_revision
            || source.checkpoint().desired_revision != source_revision
            || source.checkpoint().runtime_incarnation.as_ref() != Some(source_incarnation)
            || desired.placement != checkpoint_placement(source.checkpoint())
            || source.checkpoint().lifecycle_admission != LifecycleAdmission::Open
            || source.checkpoint().stable_state
                != Some(cats_api::runtime_reconciliation::StableState::Running)
        {
            return Err(GateReconcileError::WrongRequireIdleSource);
        }
        validate_unchanged_active_routes(source.checkpoint(), desired, None)?;
        let expected_snapshot = AdmissionSnapshot::from_checkpoint(source.checkpoint())?;
        let mut armed = stage_desired(source.checkpoint(), desired, times.before_effect)?;
        armed.step = ReconcileStep::CloseAdmission {
            require_idle_attempt_id: Some(attempt_id.clone()),
        };
        armed.require_idle = RequireIdleCheckpoint::Armed {
            attempt_id: attempt_id.clone(),
            source_revision,
            source_runtime_incarnation: source_incarnation.clone(),
        };

        let mut closed = armed.clone();
        close_checkpoint_gates(&mut closed);
        closed.require_idle = RequireIdleCheckpoint::Closed {
            attempt_id: attempt_id.clone(),
            source_revision,
            source_runtime_incarnation: source_incarnation.clone(),
        };
        closed.updated_at_unix_ms = times.after_effect;
        let replacement_snapshot = AdmissionSnapshot::from_checkpoint(&closed)?;
        let armed = self.store.replace(source, &armed)?;

        match self
            .port
            .try_close_all_if_idle(&expected_snapshot, &replacement_snapshot)
        {
            Ok(IdleCloseResult::Busy {
                platform_guards,
                endpoint_guards,
            }) if valid_guard_counts(platform_guards, &endpoint_guards, source.checkpoint()) => {
                let mut busy = armed.checkpoint().clone();
                busy.require_idle = RequireIdleCheckpoint::Busy {
                    attempt_id: attempt_id.clone(),
                    source_revision,
                    source_runtime_incarnation: source_incarnation.clone(),
                    gate_closed: false,
                    platform_guards,
                    endpoint_guards,
                };
                busy.updated_at_unix_ms = times.after_effect;
                let busy = self.store.replace(&armed, &busy)?;
                Ok(GateTransitionResult::RequireIdleBusy {
                    checkpoint: busy,
                    gate_closed: false,
                    port_error: None,
                })
            }
            Ok(IdleCloseResult::Closed) => {
                let closed = self.store.replace(&armed, &closed)?;
                Ok(GateTransitionResult::RequireIdleClosed { checkpoint: closed })
            }
            Ok(IdleCloseResult::Busy { .. }) => self.settle_armed_fail_closed(
                &armed,
                desired,
                PersistTimes {
                    before_effect: times.after_effect,
                    after_effect: times.after_effect,
                },
                Some(GatePortError::InvalidBusyEvidence),
            ),
            Err(error) => self.settle_armed_fail_closed(
                &armed,
                desired,
                PersistTimes {
                    before_effect: times.after_effect,
                    after_effect: times.after_effect,
                },
                Some(error),
            ),
        }
    }

    /// Restart recovery for a durable Armed attempt. It never evaluates idle
    /// again: Busy is persisted with `gate_closed=true` before the local close
    /// is (idempotently) enforced.
    pub fn recover_armed(
        &mut self,
        armed: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
        times: PersistTimes,
    ) -> Result<GateTransitionResult, GateReconcileError> {
        validate_times(times)?;
        applied_desired_evidence(armed.checkpoint(), desired)?;
        let (attempt_id, source_revision, source_incarnation) = require_idle_fields(desired)?;
        match &armed.checkpoint().require_idle {
            RequireIdleCheckpoint::Armed {
                attempt_id: saved_attempt,
                source_revision: saved_revision,
                source_runtime_incarnation: saved_incarnation,
            } if saved_attempt == attempt_id
                && *saved_revision == source_revision
                && saved_incarnation == source_incarnation => {}
            _ => return Err(GateReconcileError::WrongRequireIdleCheckpoint),
        }
        self.settle_armed_fail_closed(armed, desired, times, None)
    }

    /// Records a watcher/quiesce failure after a successful idle close. No
    /// gate effect is issued and the old serving epoch remains closed.
    pub fn record_post_close_busy(
        &self,
        closed: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
        updated_at: UnixMillis,
    ) -> Result<GateTransitionResult, GateReconcileError> {
        applied_desired_evidence(closed.checkpoint(), desired)?;
        let (attempt_id, source_revision, source_incarnation) = require_idle_fields(desired)?;
        if closed.checkpoint().lifecycle_admission != LifecycleAdmission::Closed
            || closed
                .checkpoint()
                .route_gates
                .iter()
                .any(|route| route.gate != RouteGateState::Closed)
        {
            return Err(GateReconcileError::GateNotClosed);
        }
        match &closed.checkpoint().require_idle {
            RequireIdleCheckpoint::Closed {
                attempt_id: saved_attempt,
                source_revision: saved_revision,
                source_runtime_incarnation: saved_incarnation,
            } if saved_attempt == attempt_id
                && *saved_revision == source_revision
                && saved_incarnation == source_incarnation => {}
            _ => return Err(GateReconcileError::WrongRequireIdleCheckpoint),
        }
        let mut busy = closed.checkpoint().clone();
        busy.require_idle = RequireIdleCheckpoint::Busy {
            attempt_id: attempt_id.clone(),
            source_revision,
            source_runtime_incarnation: source_incarnation.clone(),
            gate_closed: true,
            platform_guards: 0,
            endpoint_guards: Vec::new(),
        };
        busy.updated_at_unix_ms = updated_at;
        let busy = self.store.replace(closed, &busy)?;
        Ok(GateTransitionResult::RequireIdleBusy {
            checkpoint: busy,
            gate_closed: true,
            port_error: None,
        })
    }

    fn settle_armed_fail_closed(
        &mut self,
        armed: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
        times: PersistTimes,
        original_error: Option<GatePortError>,
    ) -> Result<GateTransitionResult, GateReconcileError> {
        applied_desired_evidence(armed.checkpoint(), desired)?;
        let (attempt_id, source_revision, source_incarnation) = require_idle_fields(desired)?;
        let expected_snapshot = AdmissionSnapshot::from_checkpoint(armed.checkpoint())?;
        let mut busy = armed.checkpoint().clone();
        close_checkpoint_gates(&mut busy);
        busy.require_idle = RequireIdleCheckpoint::Busy {
            attempt_id: attempt_id.clone(),
            source_revision,
            source_runtime_incarnation: source_incarnation.clone(),
            gate_closed: true,
            platform_guards: 0,
            endpoint_guards: Vec::new(),
        };
        busy.updated_at_unix_ms = times.before_effect;
        let replacement_snapshot = AdmissionSnapshot::from_checkpoint(&busy)?;
        let busy = self.store.replace(armed, &busy)?;
        let close_error = self
            .port
            .close_all(&expected_snapshot, &replacement_snapshot)
            .err();
        let mut completed = busy.checkpoint().clone();
        completed.updated_at_unix_ms = times.after_effect;
        let completed = self.store.replace(&busy, &completed)?;
        Ok(GateTransitionResult::RequireIdleBusy {
            checkpoint: completed,
            gate_closed: true,
            port_error: original_error.or(close_error),
        })
    }

    fn expected_transition_snapshot(
        &self,
        current: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
    ) -> Result<AdmissionSnapshot, GateReconcileError> {
        let RequireIdleCheckpoint::Busy {
            source_revision,
            source_runtime_incarnation,
            gate_closed: false,
            ..
        } = &current.checkpoint().require_idle
        else {
            return AdmissionSnapshot::from_checkpoint(current.checkpoint()).map_err(Into::into);
        };

        // Busy without a close is the one state where checkpoint metadata and
        // AdmissionCell metadata intentionally differ: the checkpoint records
        // the failed Suspended revision, while the cell remains on the source
        // Running revision. F0 intentionally does not duplicate the source
        // spec digest in RequireIdleCheckpoint, so read the real cell tuple
        // and pass that exact tuple back to the compare-and-apply operation.
        if desired.desired_revision <= current.checkpoint().desired_revision {
            return Err(GateReconcileError::WrongOpenBusySource);
        }
        let live = self.port.snapshot();
        if live.applied_desired_revision() != *source_revision
            || live.placement() != &checkpoint_placement(current.checkpoint())
            || live.runtime_incarnation() != Some(source_runtime_incarnation)
            || live.lifecycle_admission() != LifecycleAdmission::Open
            || live.endpoints() != current.checkpoint().route_gates
            || current.checkpoint().lifecycle_admission != LifecycleAdmission::Open
        {
            return Err(GateReconcileError::WrongOpenBusySource);
        }
        Ok(live)
    }
}

fn stage_desired(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    updated_at: UnixMillis,
) -> Result<RuntimeCheckpoint, GateReconcileError> {
    encode_desired_runtime_spec(desired).map_err(AppliedDesiredError::from)?;
    if checkpoint.cat_id != desired.cat_id {
        return Err(GateReconcileError::WrongCat);
    }
    if checkpoint
        .route_gates
        .iter()
        .any(|route| route.binding.workspace_id != desired.workspace_id)
    {
        return Err(GateReconcileError::WrongWorkspace);
    }
    if desired.desired_revision < checkpoint.desired_revision {
        return Err(GateReconcileError::StaleDesired {
            presented: desired.desired_revision,
            current: checkpoint.desired_revision,
        });
    }
    if desired.placement.node_id != checkpoint.node_id {
        return Err(GateReconcileError::WrongNode);
    }
    if desired.placement.placement_epoch < checkpoint.placement_epoch {
        return Err(GateReconcileError::PlacementEpochRegression);
    }
    if desired.desired_revision == checkpoint.desired_revision {
        applied_desired_evidence(checkpoint, desired)?;
    }

    let mut staged = checkpoint.clone();
    staged.desired_revision = desired.desired_revision;
    staged.spec_digest = desired.spec_digest.clone();
    staged.placement_epoch = desired.placement.placement_epoch;
    if desired.desired_revision != checkpoint.desired_revision {
        staged.stable_state = None;
        staged.require_idle = RequireIdleCheckpoint::NotApplicable;
    }
    staged.updated_at_unix_ms = updated_at;
    Ok(staged)
}

fn install_route_in_checkpoint(
    checkpoint: &mut RuntimeCheckpoint,
    binding: RouteGateBinding,
) -> Result<(), GateReconcileError> {
    let endpoint_id = binding.endpoint_id.clone();
    match checkpoint
        .route_gates
        .binary_search_by(|route| route.binding.endpoint_id.cmp(&endpoint_id))
    {
        Ok(index) => {
            let current = &checkpoint.route_gates[index];
            if binding.route_epoch < current.binding.route_epoch {
                return Err(GateReconcileError::RouteEpochRegression(endpoint_id));
            }
            if binding.route_epoch == current.binding.route_epoch {
                if binding != current.binding {
                    return Err(GateReconcileError::RouteBindingConflict(endpoint_id));
                }
                if current.gate == RouteGateState::Closed {
                    return Err(GateReconcileError::ClosedEpochReuse(endpoint_id));
                }
            } else if current.gate != RouteGateState::Closed {
                return Err(GateReconcileError::GateMustBeClosed(endpoint_id));
            }
            checkpoint.route_gates[index] = CheckpointRouteGate {
                binding,
                gate: RouteGateState::Active,
            };
        }
        Err(index) => checkpoint.route_gates.insert(
            index,
            CheckpointRouteGate {
                binding,
                gate: RouteGateState::Active,
            },
        ),
    }
    Ok(())
}

fn close_checkpoint_gates(checkpoint: &mut RuntimeCheckpoint) {
    checkpoint.lifecycle_admission = LifecycleAdmission::Closed;
    for route in &mut checkpoint.route_gates {
        route.gate = RouteGateState::Closed;
    }
}

fn require_idle_fields(
    desired: &DesiredRuntimeSpec,
) -> Result<(&RandomId128, Revision, &RandomId128), GateReconcileError> {
    match &desired.transition {
        RuntimeTransition::RequireIdle {
            attempt_id,
            source_revision,
            source_runtime_incarnation,
        } if desired.target == RuntimeTarget::Suspended => {
            Ok((attempt_id, *source_revision, source_runtime_incarnation))
        }
        _ => Err(GateReconcileError::WrongRequireIdleSource),
    }
}

fn valid_guard_counts(
    platform_guards: u32,
    endpoint_guards: &[EndpointGuardCount],
    checkpoint: &RuntimeCheckpoint,
) -> bool {
    if platform_guards == 0 && endpoint_guards.is_empty() {
        return false;
    }
    if endpoint_guards.len() > 256 || endpoint_guards.iter().any(|count| count.active_guards == 0) {
        return false;
    }
    endpoint_guards
        .windows(2)
        .all(|pair| pair[0].endpoint_id < pair[1].endpoint_id)
        && endpoint_guards.iter().all(|count| {
            checkpoint
                .route_gates
                .binary_search_by(|route| route.binding.endpoint_id.cmp(&count.endpoint_id))
                .is_ok()
        })
}

fn validate_routes_against_desired(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
) -> Result<(), AppliedDesiredError> {
    for route in &checkpoint.route_gates {
        let endpoint_id = route.binding.endpoint_id.clone();
        if route.binding.workspace_id != desired.workspace_id {
            return Err(AppliedDesiredError::RouteWorkspace { endpoint_id });
        }
        if route.gate != RouteGateState::Active {
            continue;
        }
        let endpoint = desired
            .endpoints
            .binary_search_by(|endpoint| endpoint.endpoint_id.cmp(&route.binding.endpoint_id))
            .ok()
            .and_then(|index| desired.endpoints.get(index))
            .ok_or_else(|| AppliedDesiredError::ActiveRouteMissing {
                endpoint_id: endpoint_id.clone(),
            })?;
        let expected = route_binding(desired, endpoint, checkpoint.runtime_incarnation.as_ref())
            .ok_or(AppliedDesiredError::RuntimeIncarnation)?;
        if route.binding != expected {
            return Err(AppliedDesiredError::ActiveRouteBinding { endpoint_id });
        }
    }
    Ok(())
}

fn validate_unchanged_active_routes(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    installing_endpoint: Option<&Id>,
) -> Result<(), GateReconcileError> {
    for route in checkpoint
        .route_gates
        .iter()
        .filter(|route| route.gate == RouteGateState::Active)
    {
        if installing_endpoint == Some(&route.binding.endpoint_id) {
            continue;
        }
        let Some(endpoint) = desired
            .endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == route.binding.endpoint_id)
        else {
            return Err(GateReconcileError::ActiveRouteChanged(
                route.binding.endpoint_id.clone(),
            ));
        };
        let expected = route_binding(desired, endpoint, checkpoint.runtime_incarnation.as_ref())
            .ok_or(GateReconcileError::RuntimeNotInstallable)?;
        if route.binding != expected {
            return Err(GateReconcileError::ActiveRouteChanged(
                route.binding.endpoint_id.clone(),
            ));
        }
    }
    Ok(())
}

fn route_binding(
    desired: &DesiredRuntimeSpec,
    endpoint: &EndpointIntent,
    runtime_incarnation: Option<&RandomId128>,
) -> Option<RouteGateBinding> {
    Some(RouteGateBinding {
        workspace_id: desired.workspace_id.clone(),
        endpoint_id: endpoint.endpoint_id.clone(),
        hostname: endpoint.hostname.clone(),
        cat_id: desired.cat_id.clone(),
        node_id: desired.placement.node_id.clone(),
        runtime_incarnation: runtime_incarnation?.clone(),
        route_epoch: endpoint.route_epoch,
        protocol: endpoint.protocol,
        target_port: endpoint.target_port,
    })
}

fn validate_times(times: PersistTimes) -> Result<(), GateReconcileError> {
    if times.after_effect < times.before_effect {
        Err(GateReconcileError::TimestampRegression)
    } else {
        Ok(())
    }
}

fn checkpoint_placement(checkpoint: &RuntimeCheckpoint) -> AssignedPlacement {
    AssignedPlacement {
        kind: AssignedKind::Assigned,
        node_id: checkpoint.node_id.clone(),
        placement_epoch: checkpoint.placement_epoch,
    }
}

fn contract_error(detail: ContractErrorDetail, message: &str) -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(detail),
        message: message.to_owned(),
    }
}
