//! Complete PostgreSQL snapshot consumed by the Route Grant v2 signer.
//!
//! The hostname index is only a locator.  This loader closes it against the
//! current complete Desired, provisioned NodeIdentity, fleet-owned placement
//! policy and transport target, current AgentSession, accepted full inventory,
//! latest per-Cat runtime observation, and the active signer key ACK inside one
//! repeatable-read read-only transaction. It returns no token and owns no
//! private key.

use cats_api::runtime_reconciliation::{
    key_ring_digest, Condition, Hostname, Id, KeyId, LifecycleAdmission, NodeIdentityState,
    NodeTransportTarget, ReadyReason, RouteGateState, RuntimeTarget, UnixMillis,
};

use super::placement_policy::load_policy_unlocked;
use super::product::validate_endpoint_lookup;
use super::product_rows::{
    load_desired_unlocked, load_endpoint_by_id_unlocked, load_hostname_lookup_unlocked,
};
use super::runtime_spine::{load_route_runtime_in, RouteRuntimeLoad, RouteRuntimeRejection};
use crate::route_grant_v2::{IssuedRouteGrantV2, RouteGrantV2Signer};
use crate::store::agent_sessions::load_identity_by_node_unlocked;
use crate::store::runtime_authority::gateway_identity::{
    lock_route_v2_machine_authority_shared, revalidate_gateway_principal_current_in,
    AuthenticatedGatewayPrincipal,
};
use crate::store::runtime_authority::route_signing_authority::{
    route_grant_v2_signer_is_current_in, RouteGrantV2SignerBinding,
};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{ApiError, AuthorityRequestContext, Result, Store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteGrantV2AuthoritySnapshot {
    pub(crate) workspace_id: Id,
    pub(crate) endpoint_id: Id,
    pub(crate) hostname: Hostname,
    pub(crate) cat_id: Id,
    pub(crate) node_id: Id,
    pub(crate) runtime_incarnation: cats_api::runtime_reconciliation::RandomId128,
    pub(crate) route_epoch: cats_api::runtime_reconciliation::Epoch,
    pub(crate) protocol: cats_api::runtime_reconciliation::HttpProtocol,
    pub(crate) target_port: u16,
    pub(crate) node_transport_target: NodeTransportTarget,
    pub(crate) evaluated_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteGrantV2AuthorityRejection {
    NotFound,
    Gone,
    WakeRequired,
    Pending,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteGrantV2AuthorityLoad {
    Ready(Box<RouteGrantV2AuthoritySnapshot>),
    Rejected(RouteGrantV2AuthorityRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteGrantV2MachineAuthorityLoad {
    Ready {
        snapshot: Box<RouteGrantV2AuthoritySnapshot>,
        issued: IssuedRouteGrantV2,
    },
    AuthenticationFailed,
    SignerUnavailable,
    Rejected(RouteGrantV2AuthorityRejection),
}

impl Store {
    pub(crate) fn load_route_grant_v2_authority(
        &self,
        hostname: &Hostname,
        active_signer_kid: &KeyId,
        active_guest_digest: &cats_api::runtime_reconciliation::Sha256Digest,
    ) -> Result<RouteGrantV2AuthorityLoad> {
        self.authority_read_snapshot(|transaction| {
            load_route_grant_v2_authority_in(
                transaction,
                hostname,
                active_signer_kid,
                active_guest_digest,
            )
        })
    }

    /// Revalidate Gateway, Workspace, Route facts and the in-process signer
    /// against one PG snapshot and one shared writer barrier, then sign before
    /// releasing either. No request/header value can supply the Workspace.
    pub(crate) fn issue_route_grant_v2_for_gateway(
        &self,
        hostname: &Hostname,
        principal: &AuthenticatedGatewayPrincipal,
        signer_binding: &RouteGrantV2SignerBinding,
        signer: &RouteGrantV2Signer,
        active_guest_digest: &cats_api::runtime_reconciliation::Sha256Digest,
        request: &AuthorityRequestContext,
    ) -> Result<RouteGrantV2MachineAuthorityLoad> {
        self.authority_request_locking_read_snapshot(request, |transaction| {
            lock_route_v2_machine_authority_shared(transaction)?;
            let Some(scope) = revalidate_gateway_principal_current_in(transaction, principal)?
            else {
                return Ok(RouteGrantV2MachineAuthorityLoad::AuthenticationFailed);
            };
            if signer_binding.active_kid() != Some(signer.kid()) {
                return Ok(RouteGrantV2MachineAuthorityLoad::SignerUnavailable);
            }
            if !route_grant_v2_signer_is_current_in(transaction, signer_binding)? {
                return Ok(RouteGrantV2MachineAuthorityLoad::SignerUnavailable);
            }
            let snapshot = match load_route_grant_v2_authority_in(
                transaction,
                hostname,
                signer.kid(),
                active_guest_digest,
            )? {
                RouteGrantV2AuthorityLoad::Ready(snapshot) => snapshot,
                RouteGrantV2AuthorityLoad::Rejected(rejection) => {
                    return Ok(RouteGrantV2MachineAuthorityLoad::Rejected(rejection));
                }
            };
            if !scope.authorizes_workspace(&snapshot.workspace_id) {
                return Ok(RouteGrantV2MachineAuthorityLoad::AuthenticationFailed);
            }
            let issued = signer.issue(&snapshot).map_err(|_| {
                AuthorityTransactionError::Application(ApiError::unavailable(
                    "Route Grant v2 signer could not issue from the current snapshot",
                ))
            })?;
            Ok(RouteGrantV2MachineAuthorityLoad::Ready { snapshot, issued })
        })
    }
}

fn load_route_grant_v2_authority_in(
    transaction: &mut postgres::Transaction<'_>,
    hostname: &Hostname,
    active_signer_kid: &KeyId,
    active_guest_digest: &cats_api::runtime_reconciliation::Sha256Digest,
) -> AuthorityTxResult<RouteGrantV2AuthorityLoad> {
    let Some(lookup) = load_hostname_lookup_unlocked(transaction, hostname)? else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::NotFound,
        ));
    };
    let endpoint =
        load_endpoint_by_id_unlocked(transaction, &lookup.endpoint_id)?.ok_or_else(corrupt)?;
    let desired = load_desired_unlocked(transaction, &lookup.cat_id)?.ok_or_else(corrupt)?;
    validate_endpoint_lookup(&endpoint, &lookup, &desired)?;

    let mut endpoint_bindings = desired
        .endpoints
        .iter()
        .filter(|binding| binding.endpoint_id == lookup.endpoint_id);
    let endpoint_binding = endpoint_bindings.next().ok_or_else(corrupt)?;
    if endpoint_bindings.next().is_some() || endpoint_binding.hostname != *hostname {
        return Err(corrupt());
    }

    match desired.target {
        RuntimeTarget::Running => {}
        RuntimeTarget::Suspended | RuntimeTarget::Warm | RuntimeTarget::Cold => {
            return Ok(RouteGrantV2AuthorityLoad::Rejected(
                RouteGrantV2AuthorityRejection::WakeRequired,
            ));
        }
        RuntimeTarget::Deleted => {
            return Ok(RouteGrantV2AuthorityLoad::Rejected(
                RouteGrantV2AuthorityRejection::Gone,
            ));
        }
    }

    let route = match load_route_runtime_in(
        transaction,
        &desired.placement.node_id,
        &desired.cat_id,
        active_guest_digest,
    )? {
        RouteRuntimeLoad::Accepted(snapshot) => *snapshot,
        RouteRuntimeLoad::Rejected(rejection) => {
            return Ok(RouteGrantV2AuthorityLoad::Rejected(
                classify_runtime_rejection(rejection),
            ));
        }
    };

    let attested_desired = route
        .admission
        .assigned_desired_specs
        .iter()
        .find(|candidate| candidate.cat_id == desired.cat_id)
        .ok_or_else(corrupt)?;
    if attested_desired != &desired {
        return Err(corrupt());
    }
    let Some((transport_identity, node_transport_target)) =
        load_node_transport_authority_in(transaction, &desired.placement.node_id)?
    else {
        return Err(corrupt());
    };
    if transport_identity != route.admission.node_identity
        || transport_identity.node_id != desired.placement.node_id
    {
        return Err(corrupt());
    }

    let ring_observation = &route.admission.full_inventory_observation;
    let (Some(ring_version), Some(ring_digest)) = (
        ring_observation.key_ring_version,
        ring_observation.key_ring_digest.as_ref(),
    ) else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    };
    let recomputed =
        key_ring_digest(ring_version, &ring_observation.loaded_kids).map_err(|_| corrupt())?;
    if &recomputed != ring_digest {
        return Err(corrupt());
    }
    if !ring_observation
        .loaded_kids
        .iter()
        .any(|kid| kid == active_signer_kid)
    {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    }

    let runtime = &route.runtime;
    let expected_applied = cats_api::runtime_reconciliation::AppliedDesiredEvidence {
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        target: RuntimeTarget::Running,
    };
    let Some(runtime_incarnation) = runtime.runtime_incarnation.clone() else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Pending,
        ));
    };
    let ready = runtime.conditions.iter().any(|condition| {
        matches!(
            condition,
            Condition::Ready {
                reason: ReadyReason::PostconditionSatisfied {
                    target: RuntimeTarget::Running
                }
            }
        )
    });
    let mut gates = runtime
        .routes
        .iter()
        .filter(|gate| gate.binding.endpoint_id == endpoint_binding.endpoint_id);
    let Some(gate) = gates.next() else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Pending,
        ));
    };
    if gates.next().is_some() {
        return Err(corrupt());
    }
    let exact_binding = gate.binding.workspace_id == desired.workspace_id
        && gate.binding.endpoint_id == endpoint_binding.endpoint_id
        && gate.binding.hostname == endpoint_binding.hostname
        && gate.binding.cat_id == desired.cat_id
        && gate.binding.node_id == desired.placement.node_id
        && gate.binding.runtime_incarnation == runtime_incarnation
        && gate.binding.route_epoch == endpoint_binding.route_epoch
        && gate.binding.protocol == endpoint_binding.protocol
        && gate.binding.target_port == endpoint_binding.target_port;
    if runtime.applied_desired.as_ref() != Some(&expected_applied)
        || runtime.stable_state != Some(cats_api::runtime_reconciliation::StableState::Running)
        || runtime.lifecycle_admission != LifecycleAdmission::Open
        || !ready
        || !exact_binding
        || gate.gate != RouteGateState::Active
        || gate.cancellation_pending
        || gate.instance_count != 1
    {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Pending,
        ));
    }

    Ok(RouteGrantV2AuthorityLoad::Ready(Box::new(
        RouteGrantV2AuthoritySnapshot {
            workspace_id: desired.workspace_id,
            endpoint_id: endpoint_binding.endpoint_id.clone(),
            hostname: endpoint_binding.hostname.clone(),
            cat_id: desired.cat_id,
            node_id: desired.placement.node_id,
            runtime_incarnation,
            route_epoch: endpoint_binding.route_epoch,
            protocol: endpoint_binding.protocol,
            target_port: endpoint_binding.target_port,
            node_transport_target,
            evaluated_at_unix_ms: route.admission.evaluated_at_unix_ms,
        },
    )))
}

fn load_node_transport_authority_in(
    transaction: &mut postgres::Transaction<'_>,
    node_id: &Id,
) -> std::result::Result<
    Option<(
        cats_api::runtime_reconciliation::NodeIdentity,
        NodeTransportTarget,
    )>,
    AuthorityTransactionError,
> {
    let Some(identity) = load_identity_by_node_unlocked(transaction, node_id)? else {
        return Ok(None);
    };
    if identity.state != NodeIdentityState::Provisioned {
        return Ok(None);
    }
    let policy = load_policy_unlocked(transaction, node_id)?.ok_or_else(corrupt)?;
    if identity.node_id != *node_id || policy.node_id != identity.node_id {
        return Err(corrupt());
    }
    Ok(Some((identity, policy.node_transport_target)))
}

#[cfg(test)]
impl Store {
    pub(crate) fn load_node_transport_target_for_test(
        &self,
        node_id: &Id,
    ) -> Result<Option<NodeTransportTarget>> {
        self.authority_read_snapshot(|transaction| {
            Ok(load_node_transport_authority_in(transaction, node_id)?.map(|(_, target)| target))
        })
    }
}

fn classify_runtime_rejection(rejection: RouteRuntimeRejection) -> RouteGrantV2AuthorityRejection {
    match rejection {
        RouteRuntimeRejection::RuntimeMissing => RouteGrantV2AuthorityRejection::Pending,
        RouteRuntimeRejection::Admission(_)
        | RouteRuntimeRejection::RuntimeStale
        | RouteRuntimeRejection::RuntimeSessionReplaced
        | RouteRuntimeRejection::RuntimeInventoryEpochChanged => {
            RouteGrantV2AuthorityRejection::Unavailable
        }
    }
}

fn corrupt() -> AuthorityTransactionError {
    cats_storage::authority::AuthorityError::BackendUnknown.into()
}
