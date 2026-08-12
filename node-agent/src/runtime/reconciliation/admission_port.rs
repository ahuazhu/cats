use cats_api::runtime_reconciliation::{
    AssignedKind, AssignedPlacement, CheckpointRouteGate, EndpointGuardCount, Ipv4Address,
    LifecycleAdmission, RandomId128, Revision, RuntimeCheckpoint, Sha256Digest,
};
use thiserror::Error;

/// The complete state compared at the in-memory admission linearization point.
///
/// A port implementation must compare every field. In particular, comparing
/// only an Endpoint ID or route epoch would allow a stale revision, placement,
/// or VMM incarnation to mutate a replacement runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionSnapshot {
    applied_desired_revision: Revision,
    spec_digest: Sha256Digest,
    placement: AssignedPlacement,
    runtime_incarnation: Option<RandomId128>,
    guest_ipv4: Option<Ipv4Address>,
    lifecycle_admission: LifecycleAdmission,
    endpoints: Vec<CheckpointRouteGate>,
}

impl AdmissionSnapshot {
    /// Captures an already-validated, locally owned AdmissionCell tuple.
    /// Wire decoding remains at the F0 contract boundary; this constructor is
    /// only for the in-process adapter that owns the typed cell fields.
    pub fn new(
        applied_desired_revision: Revision,
        spec_digest: Sha256Digest,
        placement: AssignedPlacement,
        runtime_incarnation: Option<RandomId128>,
        lifecycle_admission: LifecycleAdmission,
        endpoints: Vec<CheckpointRouteGate>,
    ) -> Self {
        Self {
            applied_desired_revision,
            spec_digest,
            placement,
            runtime_incarnation,
            guest_ipv4: None,
            lifecycle_admission,
            endpoints,
        }
    }

    pub fn applied_desired_revision(&self) -> Revision {
        self.applied_desired_revision
    }

    pub fn spec_digest(&self) -> &Sha256Digest {
        &self.spec_digest
    }

    pub fn placement(&self) -> &AssignedPlacement {
        &self.placement
    }

    pub fn runtime_incarnation(&self) -> Option<&RandomId128> {
        self.runtime_incarnation.as_ref()
    }

    pub fn guest_ipv4(&self) -> Option<&Ipv4Address> {
        self.guest_ipv4.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn with_guest_ipv4(mut self, guest_ipv4: Ipv4Address) -> Self {
        self.guest_ipv4 = Some(guest_ipv4);
        self
    }

    pub fn lifecycle_admission(&self) -> LifecycleAdmission {
        self.lifecycle_admission
    }

    pub fn endpoints(&self) -> &[CheckpointRouteGate] {
        &self.endpoints
    }

    /// Returns the same verified revision tuple with all work admission
    /// conservatively Closed. Port implementations use this on any ambiguous
    /// compare-and-apply failure.
    pub fn fail_closed(&self) -> Self {
        let mut closed = self.clone();
        closed.lifecycle_admission = LifecycleAdmission::Closed;
        for route in &mut closed.endpoints {
            route.gate = cats_api::runtime_reconciliation::RouteGateState::Closed;
        }
        closed
    }

    pub(super) fn from_checkpoint(checkpoint: &RuntimeCheckpoint) -> Result<Self, SnapshotError> {
        validate_route_identities(checkpoint)?;
        let guest_ipv4 = checkpoint
            .runtime_launch
            .identity()
            .map(|launch| launch.network.network_config.guest_ipv4.clone());
        let mut snapshot = Self::new(
            checkpoint.desired_revision,
            checkpoint.spec_digest.clone(),
            AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: checkpoint.node_id.clone(),
                placement_epoch: checkpoint.placement_epoch,
            },
            checkpoint.runtime_incarnation.clone(),
            checkpoint.lifecycle_admission,
            checkpoint.route_gates.clone(),
        );
        snapshot.guest_ipv4 = guest_ipv4;
        Ok(snapshot)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdleCloseResult {
    /// No gate changed. Counts describe the same linearization point.
    Busy {
        platform_guards: u32,
        endpoint_guards: Vec<EndpointGuardCount>,
    },
    /// All lifecycle and Endpoint admission changed to `replacement` in one
    /// linearization point.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GatePortError {
    #[error("the admission state matched neither the expected nor replay state")]
    StateMismatch,
    #[error("the admission cell could not complete the local operation")]
    Unavailable,
    #[error("the admission cell returned invalid Busy guard evidence")]
    InvalidBusyEvidence,
}

/// The only local-effect boundary used by the gate reconciliation spine.
///
/// Implementations run synchronously in the short `AdmissionCell` critical
/// section and perform no file, network, database, VMM, or async work. Every
/// method is an exact compare-and-apply operation:
///
/// Global operations (`close_all` and `try_close_all_if_idle`) fail closed on
/// an ambiguous result. Endpoint operations have a deliberately different
/// contract: they may mutate only the named Endpoint and the applied Desired
/// tuple. A compare mismatch has zero side effects, while `Unavailable` may
/// mean that the named effect happened; the caller confirms the complete
/// snapshot before changing the durable checkpoint. This distinction is what
/// keeps an Endpoint-A cutover from closing Endpoint B.
pub trait AdmissionGatePort {
    /// Returns one complete point-in-time copy of the local cell state.
    ///
    /// This is only needed when a successful `RequireIdle` Busy result left
    /// the cell on its source Running revision while the durable checkpoint
    /// advanced to the failed Suspended revision. The returned value is not
    /// authority by itself: a subsequent mutation must still compare the
    /// complete value as `expected` in the cell's linearization point.
    fn snapshot(&self) -> AdmissionSnapshot;

    /// Compare-opens lifecycle admission for the exact same runtime
    /// incarnation when the complete Desired contains no Endpoint. Both
    /// snapshots must have an empty Endpoint set; Endpoint-bearing Running
    /// tails use the first `install_gate` transition instead.
    fn open_lifecycle(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
    ) -> Result<(), GatePortError>;

    fn install_gate(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
        endpoint_id: &cats_api::runtime_reconciliation::Id,
    ) -> Result<(), GatePortError>;

    /// Atomically advances the applied Desired tuple and compare-closes only
    /// `endpoint_id`. `expected` and `replacement` must be identical for every
    /// other Endpoint and for lifecycle admission.
    fn close_gate(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
        endpoint_id: &cats_api::runtime_reconciliation::Id,
    ) -> Result<(), GatePortError>;

    /// Compare-removes one exact, already-Closed Endpoint entry. Existing
    /// guards are drained by the caller before invoking this method; no other
    /// Endpoint entry, guard, or cancellation handle may change.
    fn remove_closed_gate(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
        endpoint_id: &cats_api::runtime_reconciliation::Id,
    ) -> Result<(), GatePortError>;

    fn close_all(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
    ) -> Result<(), GatePortError>;

    fn try_close_all_if_idle(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
    ) -> Result<IdleCloseResult, GatePortError>;

    /// Advances only the metadata tuple of an already globally Closed cell.
    /// Both snapshots must contain the same bindings with every gate Closed;
    /// this recovery edge can never admit work or recreate a route epoch.
    fn advance_closed(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
    ) -> Result<(), GatePortError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SnapshotError {
    #[error("route gate {endpoint_id} belongs to another Cat")]
    WrongCat {
        endpoint_id: cats_api::runtime_reconciliation::Id,
    },
    #[error("route gate {endpoint_id} belongs to another Node")]
    WrongNode {
        endpoint_id: cats_api::runtime_reconciliation::Id,
    },
    #[error("route gate {endpoint_id} does not match the checkpoint runtime incarnation")]
    WrongRuntimeIncarnation {
        endpoint_id: cats_api::runtime_reconciliation::Id,
    },
}

fn validate_route_identities(checkpoint: &RuntimeCheckpoint) -> Result<(), SnapshotError> {
    for route in &checkpoint.route_gates {
        let endpoint_id = route.binding.endpoint_id.clone();
        if route.binding.cat_id != checkpoint.cat_id {
            return Err(SnapshotError::WrongCat { endpoint_id });
        }
        if route.binding.node_id != checkpoint.node_id {
            return Err(SnapshotError::WrongNode { endpoint_id });
        }
        if checkpoint.runtime_incarnation.as_ref() != Some(&route.binding.runtime_incarnation) {
            return Err(SnapshotError::WrongRuntimeIncarnation { endpoint_id });
        }
    }
    Ok(())
}
