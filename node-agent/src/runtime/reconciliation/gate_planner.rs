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
use super::checkpoint::{
    CheckpointStoreError, EndpointEffectEdge, EndpointEffectTransition,
    EndpointEffectTransitionPreparation, FileCheckpointStore, StoredCheckpoint,
};

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
    EndpointClosed {
        checkpoint: StoredCheckpoint,
        /// Retained only for diagnostics when an ambiguous local return was
        /// resolved by reading the exact closed postcondition.
        port_error: Option<GatePortError>,
    },
    EndpointPrepared {
        checkpoint: StoredCheckpoint,
    },
    EndpointRemoved {
        checkpoint: StoredCheckpoint,
        /// Retained only for diagnostics when exact absence confirmed an
        /// otherwise ambiguous compare-remove result.
        port_error: Option<GatePortError>,
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
            | Self::EndpointClosed { checkpoint, .. }
            | Self::EndpointPrepared { checkpoint }
            | Self::EndpointRemoved { checkpoint, .. }
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
    #[error("Endpoint-only gate convergence requires a Running, non-RequireIdle Desired")]
    EndpointOnlyRequiresRunning,
    #[error("Endpoint {0} is not the next deterministic Endpoint delta")]
    EndpointOutOfOrder(Id),
    #[error("Endpoint {0} does not require the requested gate action")]
    WrongEndpointAction(Id),
    #[error("checkpoint does not contain the exact durable CloseGate token for Endpoint {0}")]
    WrongCloseGateCheckpoint(Id),
    #[error("Endpoint {0} must have a durable Closed old binding")]
    EndpointNotClosed(Id),
    #[error("Endpoint {0} changed without increasing its route epoch")]
    RouteEpochNotAdvanced(Id),
    #[error("the live AdmissionCell cannot be an exact predecessor of this Endpoint effect")]
    EndpointCellMismatch,
    #[error("Endpoint {0} already has a different in-session effect edge")]
    EndpointEffectEdgeConflict(Id),
    #[error(
        "Endpoint {0} lost its in-session install capability; a fresh Desired with a higher route epoch is required"
    )]
    FreshRouteEpochRequired(Id),
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
        if desired.placement.placement_epoch != current.checkpoint().placement_epoch
            && current
                .checkpoint()
                .route_gates
                .iter()
                .any(|route| route.gate == RouteGateState::Active)
        {
            return Err(GateReconcileError::ActiveGatesAcrossPlacement);
        }
        encode_desired_runtime_spec(desired).map_err(AppliedDesiredError::from)?;
        let incarnation = current
            .checkpoint()
            .runtime_incarnation
            .as_ref()
            .ok_or(GateReconcileError::RuntimeNotInstallable)?;
        let endpoint = desired
            .endpoints
            .iter()
            .find(|endpoint| &endpoint.endpoint_id == endpoint_id)
            .ok_or_else(|| GateReconcileError::EndpointNotFound(endpoint_id.clone()))?;
        let binding = route_binding(desired, endpoint, Some(incarnation))
            .ok_or(GateReconcileError::RuntimeNotInstallable)?;

        let already_prepared = install_step_matches(current.checkpoint(), desired, endpoint_id)?;
        let open_busy_reuse = matches!(
            current.checkpoint().require_idle,
            RequireIdleCheckpoint::Busy {
                gate_closed: false,
                ..
            }
        ) && current
            .checkpoint()
            .route_gates
            .iter()
            .any(|route| route.binding == binding && route.gate == RouteGateState::Active)
            && desired.desired_revision > current.checkpoint().desired_revision;

        let (prepared_checkpoint, edge_to_arm) = if already_prepared {
            (current.checkpoint().clone(), None)
        } else {
            if !open_busy_reuse {
                let action = first_endpoint_action(current.checkpoint(), desired)?
                    .ok_or_else(|| GateReconcileError::WrongEndpointAction(endpoint_id.clone()))?;
                if action.endpoint_id() != endpoint_id {
                    return Err(GateReconcileError::EndpointOutOfOrder(endpoint_id.clone()));
                }
                let EndpointAction::Install { new_binding, .. } = action else {
                    return Err(GateReconcileError::WrongEndpointAction(endpoint_id.clone()));
                };
                if current.checkpoint().route_gates.iter().any(|route| {
                    route.binding == new_binding && route.gate == RouteGateState::Closed
                }) {
                    return Err(GateReconcileError::ClosedEpochReuse(endpoint_id.clone()));
                }
            }
            let expected = self.expected_transition_snapshot(current, desired)?;
            if self.port.snapshot() != expected {
                return Err(GateReconcileError::EndpointCellMismatch);
            }
            let mut prepared = stage_desired(current.checkpoint(), desired, times.before_effect)?;
            prepared.stable_state = None;
            prepared.require_idle = RequireIdleCheckpoint::NotApplicable;
            if !open_busy_reuse {
                prepare_install_entry(&mut prepared, binding.clone())?;
            }
            prepared.step = ReconcileStep::InstallGate {
                endpoint_id: endpoint_id.clone(),
                route_epoch: endpoint.route_epoch,
            };
            let replacement = active_install_snapshot(&prepared, endpoint_id)?;
            let edge = EndpointEffectEdge::new(expected.clone(), replacement, endpoint_id.clone());
            (prepared, Some(edge))
        };

        let mut active_checkpoint = prepared_checkpoint.clone();
        activate_install_entry(&mut active_checkpoint, &binding)?;
        active_checkpoint.lifecycle_admission = LifecycleAdmission::Open;
        active_checkpoint.stable_state = None;
        active_checkpoint.step = ReconcileStep::InstallGate {
            endpoint_id: endpoint_id.clone(),
            route_epoch: endpoint.route_epoch,
        };
        let replacement = AdmissionSnapshot::from_checkpoint(&active_checkpoint)?;
        let mut completed = active_checkpoint.clone();
        completed.updated_at_unix_ms = times.after_effect;
        advance_endpoint_checkpoint(&mut completed, desired)?;
        encode_runtime_checkpoint(&completed).map_err(|error| {
            GateReconcileError::AppliedDesired(AppliedDesiredError::CheckpointContract { error })
        })?;
        let next = self.endpoint_effect_for_step(&replacement, &completed)?;

        // The complete post-effect checkpoint and its exact next edge are now
        // known-valid. Only after that pure planning succeeds may the durable
        // active token or the local AdmissionCell change.
        let prepared = if let Some(edge) = edge_to_arm.as_ref() {
            self.publish_endpoint_checkpoint(current, &prepared_checkpoint, Some(edge))?
        } else {
            current.clone()
        };
        let live = self.port.snapshot();
        let current_edge = (live != replacement).then(|| {
            EndpointEffectEdge::new(live.clone(), replacement.clone(), endpoint_id.clone())
        });
        let transition = match self.store.prepare_endpoint_effect_transition(
            current_edge.as_ref(),
            &replacement,
            endpoint_id,
            next.as_ref(),
        )? {
            EndpointEffectTransitionPreparation::Ready(transition) => transition,
            EndpointEffectTransitionPreparation::Missing => {
                return Err(GateReconcileError::FreshRouteEpochRequired(
                    endpoint_id.clone(),
                ))
            }
            EndpointEffectTransitionPreparation::Mismatch => {
                return Err(GateReconcileError::EndpointCellMismatch)
            }
        };
        let active_storage = if active_checkpoint == *prepared.checkpoint() {
            prepared.clone()
        } else {
            self.store.replace(&prepared, &active_checkpoint)?
        };
        if live != replacement {
            let result = self.port.install_gate(&live, &replacement, endpoint_id);
            let after = self.port.snapshot();
            match result {
                Ok(()) if after != replacement => {
                    return Err(GateReconcileError::EndpointCellMismatch)
                }
                Err(_) if after == replacement => {}
                Err(error) if after == live => return Err(error.into()),
                Err(_) => return Err(GateReconcileError::EndpointCellMismatch),
                Ok(()) => {}
            }
        }

        let completed =
            self.publish_confirmed_endpoint_checkpoint(&active_storage, &completed, transition)?;
        Ok(GateTransitionResult::Installed {
            checkpoint: completed,
        })
    }

    /// Applies one deterministic Endpoint-only close. The first publication
    /// binds the checkpoint top level to the new Desired while retaining the
    /// exact old installed binding and an Active gate. Only after that token
    /// is durable may the in-memory cell compare-close the named Endpoint.
    pub fn close_gate(
        &mut self,
        current: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
        endpoint_id: &Id,
        times: PersistTimes,
    ) -> Result<GateTransitionResult, GateReconcileError> {
        validate_times(times)?;
        validate_endpoint_desired(desired)?;

        let staged_storage: StoredCheckpoint;
        let close_checkpoint = if matches!(
            &current.checkpoint().step,
            ReconcileStep::CloseGate {
                endpoint_id: saved_endpoint,
                ..
            } if saved_endpoint == endpoint_id
        ) {
            validate_close_gate_checkpoint(current.checkpoint(), desired, endpoint_id)?;
            current
        } else {
            let action = first_endpoint_action(current.checkpoint(), desired)?
                .ok_or_else(|| GateReconcileError::WrongEndpointAction(endpoint_id.clone()))?;
            if action.endpoint_id() != endpoint_id {
                return Err(GateReconcileError::EndpointOutOfOrder(endpoint_id.clone()));
            }
            if !matches!(action, EndpointAction::Close { .. }) {
                return Err(GateReconcileError::WrongEndpointAction(endpoint_id.clone()));
            }
            let predecessor = AdmissionSnapshot::from_checkpoint(current.checkpoint())?;
            if self.port.snapshot() != predecessor {
                return Err(GateReconcileError::EndpointCellMismatch);
            }

            let mut staged = stage_desired(current.checkpoint(), desired, times.before_effect)?;
            let route_epoch = route_entry(&staged, endpoint_id)?.binding.route_epoch;
            staged.stable_state = None;
            staged.require_idle = RequireIdleCheckpoint::NotApplicable;
            staged.step = ReconcileStep::CloseGate {
                endpoint_id: endpoint_id.clone(),
                route_epoch,
            };
            let edge = self
                .endpoint_effect_for_step(&predecessor, &staged)?
                .ok_or_else(|| GateReconcileError::WrongEndpointAction(endpoint_id.clone()))?;
            staged_storage = self.publish_endpoint_checkpoint(current, &staged, Some(&edge))?;
            &staged_storage
        };

        self.execute_close_gate(close_checkpoint, desired, endpoint_id, times.after_effect)
    }

    /// After Endpoint-scoped guards have drained, atomically replaces one
    /// changed old Closed binding with the higher-epoch new Closed binding and
    /// the matching InstallGate token. This method deliberately performs no
    /// AdmissionCell mutation.
    pub fn prepare_changed_gate(
        &mut self,
        closed: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
        endpoint_id: &Id,
        updated_at: UnixMillis,
    ) -> Result<GateTransitionResult, GateReconcileError> {
        validate_endpoint_desired(desired)?;
        if prepared_install_matches(closed.checkpoint(), desired, endpoint_id)? {
            return Ok(GateTransitionResult::EndpointPrepared {
                checkpoint: closed.clone(),
            });
        }
        let route_index =
            validate_close_gate_checkpoint(closed.checkpoint(), desired, endpoint_id)?;
        if closed.checkpoint().route_gates[route_index].gate != RouteGateState::Closed {
            return Err(GateReconcileError::EndpointNotClosed(endpoint_id.clone()));
        }
        let action = first_endpoint_action(closed.checkpoint(), desired)?
            .ok_or_else(|| GateReconcileError::WrongEndpointAction(endpoint_id.clone()))?;
        if action.endpoint_id() != endpoint_id {
            return Err(GateReconcileError::EndpointOutOfOrder(endpoint_id.clone()));
        }
        let EndpointAction::PrepareChanged { new_binding, .. } = action else {
            return Err(GateReconcileError::WrongEndpointAction(endpoint_id.clone()));
        };
        let predecessor = self.port.snapshot();
        if predecessor != AdmissionSnapshot::from_checkpoint(closed.checkpoint())? {
            return Err(GateReconcileError::EndpointCellMismatch);
        }

        let mut prepared = closed.checkpoint().clone();
        prepared.route_gates[route_index] = CheckpointRouteGate {
            binding: new_binding.clone(),
            gate: RouteGateState::Closed,
        };
        prepared.step = ReconcileStep::InstallGate {
            endpoint_id: endpoint_id.clone(),
            route_epoch: new_binding.route_epoch,
        };
        prepared.updated_at_unix_ms = updated_at;
        let replacement = active_install_snapshot(&prepared, endpoint_id)?;
        let edge = EndpointEffectEdge::new(predecessor, replacement, endpoint_id.clone());
        let prepared = self.publish_endpoint_checkpoint(closed, &prepared, Some(&edge))?;
        Ok(GateTransitionResult::EndpointPrepared {
            checkpoint: prepared,
        })
    }

    /// After Endpoint-scoped guards have drained, compare-removes one exact
    /// old Closed entry from the AdmissionCell. Exact absence is the only
    /// replay postcondition; only then is the checkpoint entry removed and the
    /// next deterministic Endpoint step published.
    pub fn remove_closed_gate(
        &mut self,
        closed: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
        endpoint_id: &Id,
        updated_at: UnixMillis,
    ) -> Result<GateTransitionResult, GateReconcileError> {
        validate_endpoint_desired(desired)?;
        let route_index =
            validate_close_gate_checkpoint(closed.checkpoint(), desired, endpoint_id)?;
        if closed.checkpoint().route_gates[route_index].gate != RouteGateState::Closed {
            return Err(GateReconcileError::EndpointNotClosed(endpoint_id.clone()));
        }
        let action = first_endpoint_action(closed.checkpoint(), desired)?
            .ok_or_else(|| GateReconcileError::WrongEndpointAction(endpoint_id.clone()))?;
        if action.endpoint_id() != endpoint_id {
            return Err(GateReconcileError::EndpointOutOfOrder(endpoint_id.clone()));
        }
        if !matches!(action, EndpointAction::Remove { .. }) {
            return Err(GateReconcileError::WrongEndpointAction(endpoint_id.clone()));
        }

        let expected = AdmissionSnapshot::from_checkpoint(closed.checkpoint())?;
        let mut absent_checkpoint = closed.checkpoint().clone();
        absent_checkpoint.route_gates.remove(route_index);
        let absent = AdmissionSnapshot::from_checkpoint(&absent_checkpoint)?;
        absent_checkpoint.updated_at_unix_ms = updated_at;
        advance_endpoint_checkpoint(&mut absent_checkpoint, desired)?;
        encode_runtime_checkpoint(&absent_checkpoint).map_err(|error| {
            GateReconcileError::AppliedDesired(AppliedDesiredError::CheckpointContract { error })
        })?;
        let next = self.endpoint_effect_for_step(&absent, &absent_checkpoint)?;
        let transition = match self.store.prepare_endpoint_effect_transition(
            None,
            &absent,
            endpoint_id,
            next.as_ref(),
        )? {
            EndpointEffectTransitionPreparation::Ready(transition) => transition,
            EndpointEffectTransitionPreparation::Missing
            | EndpointEffectTransitionPreparation::Mismatch => {
                return Err(GateReconcileError::EndpointCellMismatch)
            }
        };
        let live = self.port.snapshot();
        let mut port_error = None;
        if live != absent {
            if live != expected {
                return Err(GateReconcileError::EndpointCellMismatch);
            }
            let result = self
                .port
                .remove_closed_gate(&expected, &absent, endpoint_id);
            let after = self.port.snapshot();
            match result {
                Ok(()) if after != absent => return Err(GateReconcileError::EndpointCellMismatch),
                Err(error) if after == absent => port_error = Some(error),
                Err(error) if after == expected => return Err(error.into()),
                Err(_) => return Err(GateReconcileError::EndpointCellMismatch),
                Ok(()) => {}
            }
        }

        let completed =
            self.publish_confirmed_endpoint_checkpoint(closed, &absent_checkpoint, transition)?;
        Ok(GateTransitionResult::EndpointRemoved {
            checkpoint: completed,
            port_error,
        })
    }

    fn execute_close_gate(
        &mut self,
        close_checkpoint: &StoredCheckpoint,
        desired: &DesiredRuntimeSpec,
        endpoint_id: &Id,
        updated_at: UnixMillis,
    ) -> Result<GateTransitionResult, GateReconcileError> {
        let route_index =
            validate_close_gate_checkpoint(close_checkpoint.checkpoint(), desired, endpoint_id)?;
        let mut closed_checkpoint = close_checkpoint.checkpoint().clone();
        closed_checkpoint.route_gates[route_index].gate = RouteGateState::Closed;
        closed_checkpoint.updated_at_unix_ms = updated_at;
        let replacement = closed_gate_snapshot(close_checkpoint.checkpoint(), endpoint_id)?;
        encode_runtime_checkpoint(&closed_checkpoint).map_err(|error| {
            GateReconcileError::AppliedDesired(AppliedDesiredError::CheckpointContract { error })
        })?;
        let live = self.port.snapshot();
        let current_edge = (live != replacement).then(|| {
            EndpointEffectEdge::new(live.clone(), replacement.clone(), endpoint_id.clone())
        });
        let mut transition = match self.store.prepare_endpoint_effect_transition(
            current_edge.as_ref(),
            &replacement,
            endpoint_id,
            None,
        )? {
            EndpointEffectTransitionPreparation::Ready(transition) => transition,
            EndpointEffectTransitionPreparation::Missing
            | EndpointEffectTransitionPreparation::Mismatch => {
                return Err(GateReconcileError::EndpointCellMismatch)
            }
        };
        let mut port_error = None;
        if live != replacement {
            let result = self.port.close_gate(&live, &replacement, endpoint_id);
            let after = self.port.snapshot();
            match result {
                Ok(()) if after != replacement => {
                    return Err(GateReconcileError::EndpointCellMismatch)
                }
                Err(error) if after == replacement => port_error = Some(error),
                Err(error) if after == live => return Err(error.into()),
                Err(_) => return Err(GateReconcileError::EndpointCellMismatch),
                Ok(()) => {}
            }
        }

        let checkpoint = if close_checkpoint.checkpoint().route_gates[route_index].gate
            == RouteGateState::Closed
        {
            transition.confirm();
            transition.checkpoint_is_durable();
            close_checkpoint.clone()
        } else {
            self.publish_confirmed_endpoint_checkpoint(
                close_checkpoint,
                &closed_checkpoint,
                transition,
            )?
        };
        Ok(GateTransitionResult::EndpointClosed {
            checkpoint,
            port_error,
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
        let mut completed = staged.clone();
        completed.updated_at_unix_ms = times.after_effect;
        encode_runtime_checkpoint(&completed).map_err(|error| {
            GateReconcileError::AppliedDesired(AppliedDesiredError::CheckpointContract { error })
        })?;
        let staged = self.store.replace(current, &staged)?;
        let revocation = self.store.prepare_endpoint_effect_revocation()?;
        let close_result = self
            .port
            .close_all(&expected_snapshot, &replacement_snapshot);
        // Every global port error is ambiguous and fail-closed by contract.
        // Clear endpoint capabilities while the pre-acquired guard is held,
        // before returning diagnostics or attempting the final fsync.
        revocation.confirm();
        close_result?;

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
        encode_runtime_checkpoint(&closed).map_err(|error| {
            GateReconcileError::AppliedDesired(AppliedDesiredError::CheckpointContract { error })
        })?;
        let armed = self.store.replace(source, &armed)?;
        let revocation = self.store.prepare_endpoint_effect_revocation()?;

        match self
            .port
            .try_close_all_if_idle(&expected_snapshot, &replacement_snapshot)
        {
            Ok(IdleCloseResult::Busy {
                platform_guards,
                endpoint_guards,
            }) if valid_guard_counts(platform_guards, &endpoint_guards, source.checkpoint()) => {
                drop(revocation);
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
                revocation.confirm();
                let closed = self.store.replace(&armed, &closed)?;
                Ok(GateTransitionResult::RequireIdleClosed { checkpoint: closed })
            }
            Ok(IdleCloseResult::Busy { .. }) => {
                drop(revocation);
                self.settle_armed_fail_closed(
                    &armed,
                    desired,
                    PersistTimes {
                        before_effect: times.after_effect,
                        after_effect: times.after_effect,
                    },
                    Some(GatePortError::InvalidBusyEvidence),
                )
            }
            Err(error) => {
                // The port contract makes an error an ambiguous global close.
                // Revoke every Endpoint edge before any later persistence can
                // fail and strand an old effect capability.
                revocation.confirm();
                self.settle_armed_fail_closed(
                    &armed,
                    desired,
                    PersistTimes {
                        before_effect: times.after_effect,
                        after_effect: times.after_effect,
                    },
                    Some(error),
                )
            }
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
        let mut completed = busy.clone();
        completed.updated_at_unix_ms = times.after_effect;
        encode_runtime_checkpoint(&completed).map_err(|error| {
            GateReconcileError::AppliedDesired(AppliedDesiredError::CheckpointContract { error })
        })?;
        let busy = self.store.replace(armed, &busy)?;
        let revocation = self.store.prepare_endpoint_effect_revocation()?;
        let close_error = self
            .port
            .close_all(&expected_snapshot, &replacement_snapshot)
            .err();
        revocation.confirm();
        let completed = self.store.replace(&busy, &completed)?;
        Ok(GateTransitionResult::RequireIdleBusy {
            checkpoint: completed,
            gate_closed: true,
            port_error: original_error.or(close_error),
        })
    }

    fn publish_endpoint_checkpoint(
        &self,
        expected: &StoredCheckpoint,
        checkpoint: &RuntimeCheckpoint,
        next: Option<&EndpointEffectEdge>,
    ) -> Result<StoredCheckpoint, GateReconcileError> {
        let updated = if let Some(next) = next {
            self.store.arm_endpoint_effect_edge(next)?
        } else {
            true
        };
        if !updated {
            let endpoint_id = next
                .map(EndpointEffectEdge::endpoint_id)
                .ok_or(GateReconcileError::EndpointCellMismatch)?;
            return Err(GateReconcileError::EndpointEffectEdgeConflict(
                endpoint_id.clone(),
            ));
        }

        match self.store.replace(expected, checkpoint) {
            Ok(stored) => Ok(stored),
            Err(error) => {
                let published = self
                    .store
                    .confirm_durable_checkpoint(checkpoint)
                    .unwrap_or(false);
                if !published {
                    if let Some(next) = next {
                        self.store.clear_endpoint_effect_edge(next)?;
                    }
                }
                Err(error.into())
            }
        }
    }

    fn publish_confirmed_endpoint_checkpoint(
        &self,
        expected: &StoredCheckpoint,
        checkpoint: &RuntimeCheckpoint,
        mut transition: EndpointEffectTransition<'_>,
    ) -> Result<StoredCheckpoint, GateReconcileError> {
        // This is infallible: the current and next edges were validated under
        // this same held mutex before the AdmissionCell effect. From here the
        // old edge stays consumed on every return path.
        transition.confirm();
        match self.store.replace(expected, checkpoint) {
            Ok(stored) => {
                transition.checkpoint_is_durable();
                Ok(stored)
            }
            Err(error) => {
                if self
                    .store
                    .confirm_durable_checkpoint(checkpoint)
                    .unwrap_or(false)
                {
                    transition.checkpoint_is_durable();
                }
                Err(error.into())
            }
        }
    }

    fn endpoint_effect_for_step(
        &self,
        predecessor: &AdmissionSnapshot,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<Option<EndpointEffectEdge>, GateReconcileError> {
        let (endpoint_id, replacement) = match &checkpoint.step {
            ReconcileStep::InstallGate { endpoint_id, .. } => (
                endpoint_id,
                active_install_snapshot(checkpoint, endpoint_id)?,
            ),
            ReconcileStep::CloseGate { endpoint_id, .. } => {
                (endpoint_id, closed_gate_snapshot(checkpoint, endpoint_id)?)
            }
            _ => return Ok(None),
        };
        Ok(Some(EndpointEffectEdge::new(
            predecessor.clone(),
            replacement,
            endpoint_id.clone(),
        )))
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

#[derive(Debug, Clone)]
enum EndpointAction {
    Close {
        endpoint_id: Id,
    },
    PrepareChanged {
        endpoint_id: Id,
        new_binding: RouteGateBinding,
    },
    Remove {
        endpoint_id: Id,
    },
    Install {
        endpoint_id: Id,
        new_binding: RouteGateBinding,
    },
}

impl EndpointAction {
    fn endpoint_id(&self) -> &Id {
        match self {
            Self::Close { endpoint_id }
            | Self::PrepareChanged { endpoint_id, .. }
            | Self::Remove { endpoint_id }
            | Self::Install { endpoint_id, .. } => endpoint_id,
        }
    }
}

fn validate_endpoint_desired(desired: &DesiredRuntimeSpec) -> Result<(), GateReconcileError> {
    encode_desired_runtime_spec(desired).map_err(AppliedDesiredError::from)?;
    if desired.target != RuntimeTarget::Running
        || matches!(desired.transition, RuntimeTransition::RequireIdle { .. })
    {
        return Err(GateReconcileError::EndpointOnlyRequiresRunning);
    }
    Ok(())
}

fn first_endpoint_action(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
) -> Result<Option<EndpointAction>, GateReconcileError> {
    validate_endpoint_desired(desired)?;
    AdmissionSnapshot::from_checkpoint(checkpoint)?;
    if checkpoint.cat_id != desired.cat_id {
        return Err(GateReconcileError::WrongCat);
    }
    if desired.placement.node_id != checkpoint.node_id {
        return Err(GateReconcileError::WrongNode);
    }
    if checkpoint
        .route_gates
        .iter()
        .any(|route| route.binding.workspace_id != desired.workspace_id)
    {
        return Err(GateReconcileError::WrongWorkspace);
    }
    let incarnation = checkpoint
        .runtime_incarnation
        .as_ref()
        .ok_or(GateReconcileError::RuntimeNotInstallable)?;
    let mut current_index = 0;
    let mut desired_index = 0;

    while current_index < checkpoint.route_gates.len() || desired_index < desired.endpoints.len() {
        let current = checkpoint.route_gates.get(current_index);
        let endpoint = desired.endpoints.get(desired_index);
        match (current, endpoint) {
            (Some(current), Some(endpoint))
                if current.binding.endpoint_id < endpoint.endpoint_id =>
            {
                let endpoint_id = current.binding.endpoint_id.clone();
                return Ok(Some(if is_matching_close_step(checkpoint, current) {
                    EndpointAction::Remove { endpoint_id }
                } else {
                    EndpointAction::Close { endpoint_id }
                }));
            }
            (Some(current), Some(endpoint))
                if current.binding.endpoint_id > endpoint.endpoint_id =>
            {
                let new_binding = route_binding(desired, endpoint, Some(incarnation))
                    .ok_or(GateReconcileError::RuntimeNotInstallable)?;
                return Ok(Some(EndpointAction::Install {
                    endpoint_id: endpoint.endpoint_id.clone(),
                    new_binding,
                }));
            }
            (Some(current), Some(endpoint)) => {
                let new_binding = route_binding(desired, endpoint, Some(incarnation))
                    .ok_or(GateReconcileError::RuntimeNotInstallable)?;
                if current.binding == new_binding {
                    if current.gate == RouteGateState::Closed {
                        return Ok(Some(EndpointAction::Install {
                            endpoint_id: endpoint.endpoint_id.clone(),
                            new_binding,
                        }));
                    }
                    current_index += 1;
                    desired_index += 1;
                    continue;
                }
                if new_binding.route_epoch <= current.binding.route_epoch {
                    return Err(GateReconcileError::RouteEpochNotAdvanced(
                        endpoint.endpoint_id.clone(),
                    ));
                }
                let endpoint_id = endpoint.endpoint_id.clone();
                return Ok(Some(if current.gate == RouteGateState::Active {
                    EndpointAction::Close { endpoint_id }
                } else if is_matching_close_step(checkpoint, current) {
                    EndpointAction::PrepareChanged {
                        endpoint_id,
                        new_binding,
                    }
                } else {
                    EndpointAction::Install {
                        endpoint_id,
                        new_binding,
                    }
                }));
            }
            (Some(current), None) => {
                let endpoint_id = current.binding.endpoint_id.clone();
                return Ok(Some(if is_matching_close_step(checkpoint, current) {
                    EndpointAction::Remove { endpoint_id }
                } else {
                    EndpointAction::Close { endpoint_id }
                }));
            }
            (None, Some(endpoint)) => {
                let new_binding = route_binding(desired, endpoint, Some(incarnation))
                    .ok_or(GateReconcileError::RuntimeNotInstallable)?;
                return Ok(Some(EndpointAction::Install {
                    endpoint_id: endpoint.endpoint_id.clone(),
                    new_binding,
                }));
            }
            (None, None) => break,
        }
    }
    Ok(None)
}

fn is_matching_close_step(checkpoint: &RuntimeCheckpoint, route: &CheckpointRouteGate) -> bool {
    matches!(
        &checkpoint.step,
        ReconcileStep::CloseGate {
            endpoint_id,
            route_epoch,
        } if endpoint_id == &route.binding.endpoint_id
            && route_epoch == &route.binding.route_epoch
    )
}

fn validate_close_gate_checkpoint(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    endpoint_id: &Id,
) -> Result<usize, GateReconcileError> {
    validate_endpoint_desired(desired)?;
    encode_runtime_checkpoint(checkpoint).map_err(|error| {
        GateReconcileError::AppliedDesired(AppliedDesiredError::CheckpointContract { error })
    })?;
    if checkpoint.cat_id != desired.cat_id
        || checkpoint.desired_revision != desired.desired_revision
        || checkpoint.spec_digest != desired.spec_digest
        || checkpoint.placement_epoch != desired.placement.placement_epoch
        || checkpoint.node_id != desired.placement.node_id
        || checkpoint.runtime_incarnation.is_none()
        || checkpoint.lifecycle_admission != LifecycleAdmission::Open
        || !matches!(
            &checkpoint.step,
            ReconcileStep::CloseGate {
                endpoint_id: saved_endpoint,
                route_epoch,
            } if saved_endpoint == endpoint_id
                && checkpoint.route_gates.iter().any(|route| {
                    route.binding.endpoint_id == *endpoint_id
                        && route.binding.route_epoch == *route_epoch
                })
        )
    {
        return Err(GateReconcileError::WrongCloseGateCheckpoint(
            endpoint_id.clone(),
        ));
    }
    let action = first_endpoint_action(checkpoint, desired)?
        .ok_or_else(|| GateReconcileError::WrongEndpointAction(endpoint_id.clone()))?;
    if action.endpoint_id() != endpoint_id {
        return Err(GateReconcileError::EndpointOutOfOrder(endpoint_id.clone()));
    }
    if !matches!(
        action,
        EndpointAction::Close { .. }
            | EndpointAction::PrepareChanged { .. }
            | EndpointAction::Remove { .. }
    ) {
        return Err(GateReconcileError::WrongEndpointAction(endpoint_id.clone()));
    }
    checkpoint
        .route_gates
        .binary_search_by(|route| route.binding.endpoint_id.cmp(endpoint_id))
        .map_err(|_| GateReconcileError::WrongCloseGateCheckpoint(endpoint_id.clone()))
}

fn prepared_install_matches(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    endpoint_id: &Id,
) -> Result<bool, GateReconcileError> {
    if checkpoint.cat_id != desired.cat_id
        || checkpoint.desired_revision != desired.desired_revision
        || checkpoint.spec_digest != desired.spec_digest
        || checkpoint.node_id != desired.placement.node_id
        || checkpoint.placement_epoch != desired.placement.placement_epoch
    {
        return Ok(false);
    }
    let Some(incarnation) = checkpoint.runtime_incarnation.as_ref() else {
        return Ok(false);
    };
    let Some(endpoint) = desired
        .endpoints
        .iter()
        .find(|endpoint| &endpoint.endpoint_id == endpoint_id)
    else {
        return Ok(false);
    };
    let Some(expected) = route_binding(desired, endpoint, Some(incarnation)) else {
        return Ok(false);
    };
    Ok(matches!(
        &checkpoint.step,
        ReconcileStep::InstallGate {
            endpoint_id: saved_endpoint,
            route_epoch,
        } if saved_endpoint == endpoint_id && route_epoch == &expected.route_epoch
    ) && checkpoint
        .route_gates
        .iter()
        .any(|route| route.binding == expected && route.gate == RouteGateState::Closed))
}

fn install_step_matches(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    endpoint_id: &Id,
) -> Result<bool, GateReconcileError> {
    if checkpoint.cat_id != desired.cat_id
        || checkpoint.desired_revision != desired.desired_revision
        || checkpoint.spec_digest != desired.spec_digest
        || checkpoint.node_id != desired.placement.node_id
        || checkpoint.placement_epoch != desired.placement.placement_epoch
    {
        return Ok(false);
    }
    let Some(incarnation) = checkpoint.runtime_incarnation.as_ref() else {
        return Ok(false);
    };
    let Some(endpoint) = desired
        .endpoints
        .iter()
        .find(|endpoint| &endpoint.endpoint_id == endpoint_id)
    else {
        return Ok(false);
    };
    let Some(expected) = route_binding(desired, endpoint, Some(incarnation)) else {
        return Ok(false);
    };
    Ok(matches!(
        &checkpoint.step,
        ReconcileStep::InstallGate {
            endpoint_id: saved_endpoint,
            route_epoch,
        } if saved_endpoint == endpoint_id && route_epoch == &expected.route_epoch
    ) && checkpoint
        .route_gates
        .iter()
        .any(|route| route.binding == expected))
}

fn prepare_install_entry(
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
            if current.gate != RouteGateState::Closed {
                return Err(GateReconcileError::GateMustBeClosed(endpoint_id));
            }
            if current.binding != binding && binding.route_epoch <= current.binding.route_epoch {
                return Err(GateReconcileError::RouteEpochNotAdvanced(endpoint_id));
            }
            checkpoint.route_gates[index] = CheckpointRouteGate {
                binding,
                gate: RouteGateState::Closed,
            };
        }
        Err(index) => checkpoint.route_gates.insert(
            index,
            CheckpointRouteGate {
                binding,
                gate: RouteGateState::Closed,
            },
        ),
    }
    Ok(())
}

fn activate_install_entry(
    checkpoint: &mut RuntimeCheckpoint,
    binding: &RouteGateBinding,
) -> Result<(), GateReconcileError> {
    let endpoint_id = binding.endpoint_id.clone();
    let index = checkpoint
        .route_gates
        .binary_search_by(|route| route.binding.endpoint_id.cmp(&endpoint_id))
        .map_err(|_| GateReconcileError::EndpointNotFound(endpoint_id.clone()))?;
    if checkpoint.route_gates[index].binding != *binding {
        return Err(GateReconcileError::RouteBindingConflict(endpoint_id));
    }
    checkpoint.route_gates[index].gate = RouteGateState::Active;
    Ok(())
}

fn active_install_snapshot(
    checkpoint: &RuntimeCheckpoint,
    endpoint_id: &Id,
) -> Result<AdmissionSnapshot, GateReconcileError> {
    let binding = route_entry(checkpoint, endpoint_id)?.binding.clone();
    if !matches!(
        &checkpoint.step,
        ReconcileStep::InstallGate {
            endpoint_id: saved_endpoint,
            route_epoch,
        } if saved_endpoint == endpoint_id && route_epoch == &binding.route_epoch
    ) {
        return Err(GateReconcileError::WrongEndpointAction(endpoint_id.clone()));
    }
    let mut active = checkpoint.clone();
    activate_install_entry(&mut active, &binding)?;
    active.lifecycle_admission = LifecycleAdmission::Open;
    AdmissionSnapshot::from_checkpoint(&active).map_err(Into::into)
}

fn closed_gate_snapshot(
    checkpoint: &RuntimeCheckpoint,
    endpoint_id: &Id,
) -> Result<AdmissionSnapshot, GateReconcileError> {
    let route = route_entry(checkpoint, endpoint_id)?;
    if !matches!(
        &checkpoint.step,
        ReconcileStep::CloseGate {
            endpoint_id: saved_endpoint,
            route_epoch,
        } if saved_endpoint == endpoint_id && route_epoch == &route.binding.route_epoch
    ) {
        return Err(GateReconcileError::WrongCloseGateCheckpoint(
            endpoint_id.clone(),
        ));
    }
    let mut closed = checkpoint.clone();
    let route_index = closed
        .route_gates
        .binary_search_by(|route| route.binding.endpoint_id.cmp(endpoint_id))
        .map_err(|_| GateReconcileError::EndpointNotFound(endpoint_id.clone()))?;
    closed.route_gates[route_index].gate = RouteGateState::Closed;
    AdmissionSnapshot::from_checkpoint(&closed).map_err(Into::into)
}

fn advance_endpoint_checkpoint(
    checkpoint: &mut RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
) -> Result<(), GateReconcileError> {
    match first_endpoint_action(checkpoint, desired)? {
        Some(EndpointAction::Close { endpoint_id }) => {
            let route_epoch = route_entry(checkpoint, &endpoint_id)?.binding.route_epoch;
            checkpoint.stable_state = None;
            checkpoint.step = ReconcileStep::CloseGate {
                endpoint_id,
                route_epoch,
            };
        }
        Some(EndpointAction::PrepareChanged {
            endpoint_id,
            new_binding,
        })
        | Some(EndpointAction::Install {
            endpoint_id,
            new_binding,
        }) => {
            match checkpoint
                .route_gates
                .binary_search_by(|route| route.binding.endpoint_id.cmp(&endpoint_id))
            {
                Ok(index) => {
                    if checkpoint.route_gates[index].gate != RouteGateState::Closed {
                        return Err(GateReconcileError::GateMustBeClosed(endpoint_id));
                    }
                    checkpoint.route_gates[index] = CheckpointRouteGate {
                        binding: new_binding.clone(),
                        gate: RouteGateState::Closed,
                    };
                }
                Err(index) => checkpoint.route_gates.insert(
                    index,
                    CheckpointRouteGate {
                        binding: new_binding.clone(),
                        gate: RouteGateState::Closed,
                    },
                ),
            }
            checkpoint.stable_state = None;
            checkpoint.step = ReconcileStep::InstallGate {
                endpoint_id,
                route_epoch: new_binding.route_epoch,
            };
        }
        Some(EndpointAction::Remove { endpoint_id }) => {
            return Err(GateReconcileError::WrongEndpointAction(endpoint_id))
        }
        None => {
            checkpoint.stable_state = Some(cats_api::runtime_reconciliation::StableState::Running);
            checkpoint.step = ReconcileStep::Stable {
                state: cats_api::runtime_reconciliation::StableState::Running,
            };
        }
    }
    Ok(())
}

fn route_entry<'a>(
    checkpoint: &'a RuntimeCheckpoint,
    endpoint_id: &Id,
) -> Result<&'a CheckpointRouteGate, GateReconcileError> {
    checkpoint
        .route_gates
        .binary_search_by(|route| route.binding.endpoint_id.cmp(endpoint_id))
        .ok()
        .and_then(|index| checkpoint.route_gates.get(index))
        .ok_or_else(|| GateReconcileError::EndpointNotFound(endpoint_id.clone()))
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
