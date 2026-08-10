//! In-memory Route v2 admission linearization point.
//!
//! The cell owns no network, filesystem, VMM or async work. Reconciliation
//! compare-and-applies complete snapshots through [`AdmissionCellPort`], while
//! request admission compares a verified Grant and increments its Endpoint
//! guard under the same mutex. The returned guards release on every Drop path.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use cats_api::route_grant_v2::{
    RouteAdmissionV2Reason, RouteGrantV2Claims, RouteGrantV2TimeVerdict,
};
use cats_api::runtime_reconciliation::{
    CheckpointRouteGate, EndpointGuardCount, Id, LifecycleAdmission, RouteGateState,
};
use thiserror::Error;

use super::admission_port::{AdmissionGatePort, AdmissionSnapshot, GatePortError, IdleCloseResult};

const MAX_ADMISSION_ENDPOINTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdmissionCellBuildError {
    #[error("the AdmissionCell has too many Endpoint gates")]
    TooManyEndpoints,
    #[error("Endpoint gates are not in strict Endpoint ID order")]
    EndpointOrder,
    #[error("Endpoint {endpoint_id} has an invalid target port")]
    InvalidTargetPort { endpoint_id: Id },
    #[error("Endpoint {endpoint_id} does not match the cell placement")]
    WrongPlacement { endpoint_id: Id },
    #[error("Endpoint {endpoint_id} does not match the cell runtime incarnation")]
    WrongRuntimeIncarnation { endpoint_id: Id },
    #[error("Endpoint {endpoint_id} belongs to another Cat or Workspace")]
    WrongOwner { endpoint_id: Id },
    #[error("an Active Endpoint cannot exist while lifecycle admission is Closed")]
    ActiveWhileLifecycleClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionGuardCounts {
    pub platform_guards: u32,
    pub endpoint_guards: Vec<EndpointGuardCount>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PlatformAdmissionError {
    #[error("platform admission is closed")]
    Closed,
    #[error("the AdmissionCell is unavailable")]
    Unavailable,
    #[error("the platform guard counter is exhausted")]
    CounterExhausted,
}

#[derive(Debug)]
struct CellState {
    snapshot: AdmissionSnapshot,
    platform_guards: u32,
    endpoint_guards: BTreeMap<Id, u32>,
}

/// One Cat's live admission state.
///
/// Construction and every replacement validate the complete local tuple.
/// Poisoned state never admits new work and is conservatively closed when a
/// reconciliation or observation path next obtains the mutex.
#[derive(Debug)]
pub struct AdmissionCell {
    state: Mutex<CellState>,
}

impl AdmissionCell {
    pub fn new(snapshot: AdmissionSnapshot) -> Result<Arc<Self>, AdmissionCellBuildError> {
        validate_snapshot(&snapshot)?;
        let endpoint_guards = snapshot
            .endpoints()
            .iter()
            .map(|route| (route.binding.endpoint_id.clone(), 0))
            .collect();
        Ok(Arc::new(Self {
            state: Mutex::new(CellState {
                snapshot,
                platform_guards: 0,
                endpoint_guards,
            }),
        }))
    }

    pub fn port(self: &Arc<Self>) -> AdmissionCellPort {
        AdmissionCellPort {
            cell: Arc::clone(self),
        }
    }

    pub fn snapshot(&self) -> AdmissionSnapshot {
        self.lock_observing().snapshot.clone()
    }

    pub fn guard_counts(&self) -> AdmissionGuardCounts {
        let state = self.lock_observing();
        AdmissionGuardCounts {
            platform_guards: state.platform_guards,
            endpoint_guards: nonzero_endpoint_guards(&state.endpoint_guards),
        }
    }

    pub fn active_guards(&self, endpoint_id: &Id) -> Option<u32> {
        self.lock_observing()
            .endpoint_guards
            .get(endpoint_id)
            .copied()
    }

    /// Acquires a platform-wide guard for a future control/exec consumer.
    /// Route admission uses the narrower Endpoint guard below.
    pub fn try_acquire_platform(
        self: &Arc<Self>,
    ) -> Result<PlatformAdmissionGuard, PlatformAdmissionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PlatformAdmissionError::Unavailable)?;
        if state.snapshot.lifecycle_admission() != LifecycleAdmission::Open
            || state.snapshot.runtime_incarnation().is_none()
        {
            return Err(PlatformAdmissionError::Closed);
        }
        state.platform_guards = state
            .platform_guards
            .checked_add(1)
            .ok_or(PlatformAdmissionError::CounterExhausted)?;
        Ok(PlatformAdmissionGuard {
            cell: Arc::clone(self),
        })
    }

    pub(crate) fn acquire_verified_route(
        self: &Arc<Self>,
        claims: &RouteGrantV2Claims,
        time_verdict: RouteGrantV2TimeVerdict,
    ) -> Result<RouteAdmissionGuard, RouteAdmissionV2Reason> {
        let mut state = self.lock_for_admission()?;
        let placement = state.snapshot.placement();
        if placement.node_id != claims.node_id {
            return Err(RouteAdmissionV2Reason::BindingMismatch);
        }
        let Some(runtime_incarnation) = state.snapshot.runtime_incarnation() else {
            return Err(RouteAdmissionV2Reason::RuntimeNotReady);
        };
        if runtime_incarnation != &claims.runtime_incarnation {
            return Err(RouteAdmissionV2Reason::BindingMismatch);
        }
        let route = state
            .snapshot
            .endpoints()
            .iter()
            .find(|route| route.binding.endpoint_id == claims.endpoint_id)
            .ok_or(RouteAdmissionV2Reason::BindingMismatch)?;
        if !binding_matches_claims(route, claims) {
            return Err(RouteAdmissionV2Reason::BindingMismatch);
        }
        if state.snapshot.lifecycle_admission() != LifecycleAdmission::Open
            || route.gate == RouteGateState::Closed
        {
            return Err(RouteAdmissionV2Reason::GateClosed);
        }
        match time_verdict {
            RouteGrantV2TimeVerdict::NotYetValid => {
                return Err(RouteAdmissionV2Reason::NotYetValid);
            }
            RouteGrantV2TimeVerdict::Expired => return Err(RouteAdmissionV2Reason::Expired),
            RouteGrantV2TimeVerdict::Valid => {}
        }
        let count = state
            .endpoint_guards
            .get_mut(&claims.endpoint_id)
            .ok_or(RouteAdmissionV2Reason::RuntimeNotReady)?;
        *count = count
            .checked_add(1)
            .ok_or(RouteAdmissionV2Reason::RuntimeNotReady)?;
        Ok(RouteAdmissionGuard {
            cell: Arc::clone(self),
            endpoint_id: claims.endpoint_id.clone(),
        })
    }

    fn lock_for_admission(&self) -> Result<MutexGuard<'_, CellState>, RouteAdmissionV2Reason> {
        self.state
            .lock()
            .map_err(|_| RouteAdmissionV2Reason::RuntimeNotReady)
    }

    fn lock_observing(&self) -> MutexGuard<'_, CellState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.snapshot = state.snapshot.fail_closed();
                state
            }
        }
    }

    fn release_endpoint(&self, endpoint_id: &Id) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = state.endpoint_guards.get_mut(endpoint_id) {
            if *count == 0 {
                state.snapshot = state.snapshot.fail_closed();
            } else {
                *count -= 1;
            }
        } else {
            state.snapshot = state.snapshot.fail_closed();
        }
    }

    fn release_platform(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.platform_guards == 0 {
            state.snapshot = state.snapshot.fail_closed();
        } else {
            state.platform_guards -= 1;
        }
    }
}

/// Endpoint guard held for the complete admitted request/stream lifetime.
#[derive(Debug)]
pub struct RouteAdmissionGuard {
    cell: Arc<AdmissionCell>,
    endpoint_id: Id,
}

impl RouteAdmissionGuard {
    pub fn endpoint_id(&self) -> &Id {
        &self.endpoint_id
    }
}

impl Drop for RouteAdmissionGuard {
    fn drop(&mut self) {
        self.cell.release_endpoint(&self.endpoint_id);
    }
}

#[derive(Debug)]
pub struct PlatformAdmissionGuard {
    cell: Arc<AdmissionCell>,
}

impl Drop for PlatformAdmissionGuard {
    fn drop(&mut self) {
        self.cell.release_platform();
    }
}

/// Cloneable reconciliation adapter over the same cell used by request
/// admission. The trait's `&mut self` requirement serializes planner use; the
/// cell mutex provides the actual route/close linearization point.
#[derive(Debug, Clone)]
pub struct AdmissionCellPort {
    cell: Arc<AdmissionCell>,
}

impl AdmissionCellPort {
    fn lock_mutating(&self) -> Result<MutexGuard<'_, CellState>, GatePortError> {
        match self.cell.state.lock() {
            Ok(state) => Ok(state),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.snapshot = state.snapshot.fail_closed();
                Err(GatePortError::Unavailable)
            }
        }
    }
}

impl AdmissionGatePort for AdmissionCellPort {
    fn snapshot(&self) -> AdmissionSnapshot {
        self.cell.snapshot()
    }

    fn install_gate(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
        endpoint_id: &Id,
    ) -> Result<(), GatePortError> {
        validate_snapshot(replacement).map_err(|_| GatePortError::Unavailable)?;
        if !valid_endpoint_top_transition(expected, replacement)
            || !other_endpoints_equal(expected, replacement, endpoint_id)
            || !valid_install_transition(expected, replacement, endpoint_id)
        {
            return Err(GatePortError::Unavailable);
        }
        let mut state = self.lock_mutating()?;
        if &state.snapshot == replacement {
            return Ok(());
        }
        if &state.snapshot != expected {
            return Err(GatePortError::StateMismatch);
        }
        let changed_binding = endpoint(expected, endpoint_id).map(|route| &route.binding)
            != endpoint(replacement, endpoint_id).map(|route| &route.binding);
        if changed_binding
            && state
                .endpoint_guards
                .get(endpoint_id)
                .is_some_and(|count| *count != 0)
        {
            return Err(GatePortError::Unavailable);
        }
        state.snapshot = replacement.clone();
        reconcile_guard_keys(&mut state);
        Ok(())
    }

    fn close_gate(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
        endpoint_id: &Id,
    ) -> Result<(), GatePortError> {
        validate_snapshot(replacement).map_err(|_| GatePortError::Unavailable)?;
        if !valid_endpoint_top_transition(expected, replacement)
            || !other_endpoints_equal(expected, replacement, endpoint_id)
            || !valid_close_transition(expected, replacement, endpoint_id)
        {
            return Err(GatePortError::Unavailable);
        }
        let mut state = self.lock_mutating()?;
        if &state.snapshot == replacement {
            return Ok(());
        }
        if &state.snapshot != expected {
            return Err(GatePortError::StateMismatch);
        }
        state.snapshot = replacement.clone();
        Ok(())
    }

    fn remove_closed_gate(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
        endpoint_id: &Id,
    ) -> Result<(), GatePortError> {
        validate_snapshot(replacement).map_err(|_| GatePortError::Unavailable)?;
        if !valid_endpoint_top_transition(expected, replacement)
            || !other_endpoints_equal(expected, replacement, endpoint_id)
            || !matches!(endpoint(expected, endpoint_id), Some(route) if route.gate == RouteGateState::Closed)
            || endpoint(replacement, endpoint_id).is_some()
        {
            return Err(GatePortError::Unavailable);
        }
        let mut state = self.lock_mutating()?;
        if &state.snapshot == replacement {
            return Ok(());
        }
        if &state.snapshot != expected {
            return Err(GatePortError::StateMismatch);
        }
        if state
            .endpoint_guards
            .get(endpoint_id)
            .is_none_or(|count| *count != 0)
        {
            return Err(GatePortError::Unavailable);
        }
        state.snapshot = replacement.clone();
        state.endpoint_guards.remove(endpoint_id);
        Ok(())
    }

    fn close_all(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
    ) -> Result<(), GatePortError> {
        validate_global_close(expected, replacement)?;
        let mut state = self.lock_mutating()?;
        if &state.snapshot == replacement {
            return Ok(());
        }
        if &state.snapshot != expected {
            state.snapshot = state.snapshot.fail_closed();
            return Err(GatePortError::StateMismatch);
        }
        state.snapshot = replacement.clone();
        Ok(())
    }

    fn try_close_all_if_idle(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
    ) -> Result<IdleCloseResult, GatePortError> {
        validate_global_close(expected, replacement)?;
        let mut state = self.lock_mutating()?;
        if &state.snapshot == replacement {
            return Ok(IdleCloseResult::Closed);
        }
        if &state.snapshot != expected {
            state.snapshot = state.snapshot.fail_closed();
            return Err(GatePortError::StateMismatch);
        }
        let endpoint_guards = nonzero_endpoint_guards(&state.endpoint_guards);
        if state.platform_guards != 0 || !endpoint_guards.is_empty() {
            return Ok(IdleCloseResult::Busy {
                platform_guards: state.platform_guards,
                endpoint_guards,
            });
        }
        state.snapshot = replacement.clone();
        Ok(IdleCloseResult::Closed)
    }
}

fn validate_snapshot(snapshot: &AdmissionSnapshot) -> Result<(), AdmissionCellBuildError> {
    if snapshot.endpoints().len() > MAX_ADMISSION_ENDPOINTS {
        return Err(AdmissionCellBuildError::TooManyEndpoints);
    }
    let mut seen = BTreeSet::new();
    let mut previous_endpoint_id: Option<&Id> = None;
    let mut owner = None;
    for route in snapshot.endpoints() {
        let endpoint_id = route.binding.endpoint_id.clone();
        if previous_endpoint_id.is_some_and(|previous| previous >= &endpoint_id)
            || !seen.insert(endpoint_id.clone())
        {
            return Err(AdmissionCellBuildError::EndpointOrder);
        }
        previous_endpoint_id = Some(&route.binding.endpoint_id);
        if route.binding.target_port == 0 {
            return Err(AdmissionCellBuildError::InvalidTargetPort { endpoint_id });
        }
        if route.binding.node_id != snapshot.placement().node_id {
            return Err(AdmissionCellBuildError::WrongPlacement { endpoint_id });
        }
        if snapshot.runtime_incarnation() != Some(&route.binding.runtime_incarnation) {
            return Err(AdmissionCellBuildError::WrongRuntimeIncarnation { endpoint_id });
        }
        let route_owner = (&route.binding.workspace_id, &route.binding.cat_id);
        if owner.is_none() {
            owner = Some(route_owner);
        } else if owner != Some(route_owner) {
            return Err(AdmissionCellBuildError::WrongOwner { endpoint_id });
        }
        if snapshot.lifecycle_admission() == LifecycleAdmission::Closed
            && route.gate == RouteGateState::Active
        {
            return Err(AdmissionCellBuildError::ActiveWhileLifecycleClosed);
        }
    }
    Ok(())
}

fn binding_matches_claims(route: &CheckpointRouteGate, claims: &RouteGrantV2Claims) -> bool {
    let binding = &route.binding;
    binding.workspace_id == claims.workspace_id
        && binding.endpoint_id == claims.endpoint_id
        && binding.hostname == claims.hostname
        && binding.cat_id == claims.cat_id
        && binding.node_id == claims.node_id
        && binding.runtime_incarnation == claims.runtime_incarnation
        && binding.route_epoch == claims.route_epoch
        && binding.protocol == claims.protocol
        && binding.target_port == claims.target_port
}

fn endpoint<'a>(
    snapshot: &'a AdmissionSnapshot,
    endpoint_id: &Id,
) -> Option<&'a CheckpointRouteGate> {
    snapshot
        .endpoints()
        .iter()
        .find(|route| &route.binding.endpoint_id == endpoint_id)
}

fn other_endpoints_equal(
    expected: &AdmissionSnapshot,
    replacement: &AdmissionSnapshot,
    endpoint_id: &Id,
) -> bool {
    expected
        .endpoints()
        .iter()
        .filter(|route| &route.binding.endpoint_id != endpoint_id)
        .eq(replacement
            .endpoints()
            .iter()
            .filter(|route| &route.binding.endpoint_id != endpoint_id))
}

fn valid_endpoint_top_transition(
    expected: &AdmissionSnapshot,
    replacement: &AdmissionSnapshot,
) -> bool {
    expected.placement() == replacement.placement()
        && expected.runtime_incarnation() == replacement.runtime_incarnation()
        && expected.lifecycle_admission() == replacement.lifecycle_admission()
        && replacement.applied_desired_revision() >= expected.applied_desired_revision()
        && (replacement.applied_desired_revision() > expected.applied_desired_revision()
            || replacement.spec_digest() == expected.spec_digest())
}

fn valid_install_transition(
    expected: &AdmissionSnapshot,
    replacement: &AdmissionSnapshot,
    endpoint_id: &Id,
) -> bool {
    let Some(next) = endpoint(replacement, endpoint_id) else {
        return false;
    };
    if next.gate != RouteGateState::Active
        || replacement.lifecycle_admission() != LifecycleAdmission::Open
    {
        return false;
    }
    match endpoint(expected, endpoint_id) {
        None => true,
        Some(current) if current.binding == next.binding => current.gate == RouteGateState::Active,
        Some(current) => {
            current.gate == RouteGateState::Closed
                && next.binding.route_epoch > current.binding.route_epoch
                && next.binding.workspace_id == current.binding.workspace_id
                && next.binding.cat_id == current.binding.cat_id
        }
    }
}

fn valid_close_transition(
    expected: &AdmissionSnapshot,
    replacement: &AdmissionSnapshot,
    endpoint_id: &Id,
) -> bool {
    matches!(
        (endpoint(expected, endpoint_id), endpoint(replacement, endpoint_id)),
        (Some(current), Some(next))
            if current.binding == next.binding && next.gate == RouteGateState::Closed
    )
}

fn validate_global_close(
    expected: &AdmissionSnapshot,
    replacement: &AdmissionSnapshot,
) -> Result<(), GatePortError> {
    validate_snapshot(replacement).map_err(|_| GatePortError::Unavailable)?;
    if replacement.lifecycle_admission() != LifecycleAdmission::Closed
        || replacement
            .endpoints()
            .iter()
            .any(|route| route.gate != RouteGateState::Closed)
        || expected.endpoints().len() != replacement.endpoints().len()
        || expected
            .endpoints()
            .iter()
            .zip(replacement.endpoints())
            .any(|(current, next)| current.binding != next.binding)
    {
        return Err(GatePortError::Unavailable);
    }
    Ok(())
}

fn reconcile_guard_keys(state: &mut CellState) {
    state.endpoint_guards.retain(|endpoint_id, _| {
        state
            .snapshot
            .endpoints()
            .iter()
            .any(|route| &route.binding.endpoint_id == endpoint_id)
    });
    for route in state.snapshot.endpoints() {
        state
            .endpoint_guards
            .entry(route.binding.endpoint_id.clone())
            .or_insert(0);
    }
}

fn nonzero_endpoint_guards(counts: &BTreeMap<Id, u32>) -> Vec<EndpointGuardCount> {
    counts
        .iter()
        .filter(|(_, count)| **count != 0)
        .map(|(endpoint_id, active_guards)| EndpointGuardCount {
            endpoint_id: endpoint_id.clone(),
            active_guards: *active_guards,
        })
        .collect()
}
