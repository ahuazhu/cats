//! Complete PostgreSQL snapshot consumed by the Route Grant v2 signer.
//!
//! The hostname index is only a locator.  This loader closes it against the
//! current complete Desired, current AgentSession, accepted full inventory,
//! latest per-Cat runtime observation, and the active signer key ACK inside
//! one repeatable-read read-only transaction.  It returns no token and owns no
//! private key.

use cats_api::runtime_reconciliation::{
    key_ring_digest, Condition, Hostname, Id, KeyId, LifecycleAdmission, ReadyReason,
    RouteGateState, RuntimeTarget, UnixMillis,
};

use super::product::validate_endpoint_lookup;
use super::product_rows::{
    load_desired_unlocked, load_endpoint_by_id_unlocked, load_hostname_lookup_unlocked,
};
use super::runtime_spine::{load_route_runtime_in, RouteRuntimeLoad, RouteRuntimeRejection};
use crate::store::transaction::AuthorityTransactionError;
use crate::store::{Result, Store};

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

impl Store {
    pub(crate) fn load_route_grant_v2_authority(
        &self,
        hostname: &Hostname,
        active_signer_kid: &KeyId,
        active_guest_digest: &cats_api::runtime_reconciliation::Sha256Digest,
    ) -> Result<RouteGrantV2AuthorityLoad> {
        self.authority_read_snapshot(|transaction| {
            let Some(lookup) = load_hostname_lookup_unlocked(transaction, hostname)? else {
                return Ok(RouteGrantV2AuthorityLoad::Rejected(
                    RouteGrantV2AuthorityRejection::NotFound,
                ));
            };
            let endpoint = load_endpoint_by_id_unlocked(transaction, &lookup.endpoint_id)?
                .ok_or_else(corrupt)?;
            let desired =
                load_desired_unlocked(transaction, &lookup.cat_id)?.ok_or_else(corrupt)?;
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

            let ring_observation = &route.admission.full_inventory_observation;
            let (Some(ring_version), Some(ring_digest)) = (
                ring_observation.key_ring_version,
                ring_observation.key_ring_digest.as_ref(),
            ) else {
                return Ok(RouteGrantV2AuthorityLoad::Rejected(
                    RouteGrantV2AuthorityRejection::Unavailable,
                ));
            };
            let recomputed = key_ring_digest(ring_version, &ring_observation.loaded_kids)
                .map_err(|_| corrupt())?;
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
                || runtime.stable_state
                    != Some(cats_api::runtime_reconciliation::StableState::Running)
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
                    evaluated_at_unix_ms: route.admission.evaluated_at_unix_ms,
                },
            )))
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
