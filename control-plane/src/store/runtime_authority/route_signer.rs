//! Atomic Route Grant v2 signing snapshot.
//!
//! The hostname index is only a locator. Signable serving authority is the
//! exact current Endpoint binding, current lifecycle effective RuntimeReady,
//! one terminal Serving Route receipt and the current AgentSession. A fresh
//! session-bound full-inventory attestation and exact public-ring ACK are
//! additional delivery prerequisites; neither can manufacture Serving.
//!
//! Desired, assigned snapshots and Running/route Observation are deliberately
//! absent from this module.

use cats_api::runtime_inventory::RuntimeInventoryAttestation;
use cats_api::runtime_reconciliation::{
    key_ring_digest, AgentSession, Epoch, Hostname, HttpProtocol, Id, KeyId, NodeIdentityState,
    NodeTransportTarget, RandomId128, Sequence, SessionBinding, Sha256Digest, UnixMillis,
};
use cats_api::runtime_route::{
    decode_route_command_envelope, decode_route_command_response,
    decode_route_control_invalidation, decode_route_node_ring_ack, encode_route_command_response,
    encode_route_control_invalidation, route_terminal_result_digest, validate_route_operation,
    RouteCommand, RouteCommandPredecessor, RouteNodeResult, RouteNodeRingAck, RouteOperation,
    RouteOperationState, RouteOperationTerminal, RouteServingBinding, RouteTerminalResultKind,
};
use cats_storage::authority::AuthorityError;
use postgres::Row;

use super::lifecycle_commands::{
    load_lifecycle_route_authority_snapshot_in, LifecycleRouteAuthority, LifecycleStableState,
};
use super::pg_codec::PgBigInt;
use super::placement_policy::load_policy_unlocked;
#[cfg(test)]
use super::route_signing_authority::load_current_signer;
use super::route_signing_authority::{
    route_grant_v2_signer_is_current_in, RouteGrantV2SignerBinding,
};
use super::rows::database_now;
use super::runtime_spine::{
    load_runtime_full_inventory_unlocked, RuntimeFullInventoryState, PLACEMENT_INVENTORY_MAX_AGE_MS,
};
use crate::route_grant_v2::{IssuedRouteGrantV2, RouteGrantV2Signer};
use crate::store::agent_sessions::{load_current_session_unlocked, load_identity_by_node_unlocked};
use crate::store::runtime_authority::gateway_identity::{
    lock_route_v2_machine_authority_shared, revalidate_gateway_principal_current_in,
    AuthenticatedGatewayPrincipal,
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
    pub(crate) runtime_incarnation: RandomId128,
    pub(crate) route_epoch: Epoch,
    pub(crate) protocol: HttpProtocol,
    pub(crate) target_port: u16,
    pub(crate) node_transport_target: NodeTransportTarget,
    pub(crate) evaluated_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteGrantV2AuthorityRejection {
    NotFound,
    Gone,
    RunRequired,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrentEndpointRouteBinding {
    workspace_id: Id,
    cat_id: Id,
    endpoint_id: Id,
    hostname: Hostname,
    protocol: HttpProtocol,
    target_port: u16,
    route_epoch: Epoch,
    effective_serving_operation_id: Option<Id>,
}

struct RouteGrantV2AuthorityLocator {
    endpoint: CurrentEndpointRouteBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoredRouteRingAck {
    pub(super) ack: RouteNodeRingAck,
    pub(super) accepted_at_unix_ms: UnixMillis,
}

struct AtomicRouteSignerFacts<'a> {
    endpoint: &'a CurrentEndpointRouteBinding,
    lifecycle: &'a LifecycleRouteAuthority,
    serving_operation: &'a RouteOperation,
    current_session: &'a AgentSession,
    inventory: &'a RuntimeFullInventoryState,
    ring_ack: &'a StoredRouteRingAck,
    signer_binding: &'a RouteGrantV2SignerBinding,
    active_signer_kid: &'a KeyId,
    node_transport_target: NodeTransportTarget,
    evaluated_at_unix_ms: UnixMillis,
}

impl Store {
    #[cfg(test)]
    pub(crate) fn load_route_grant_v2_authority(
        &self,
        hostname: &Hostname,
        active_signer_kid: &KeyId,
        // Transitional caller argument only; deliberately not authority.
        _legacy_active_guest_digest: &Sha256Digest,
    ) -> Result<RouteGrantV2AuthorityLoad> {
        self.authority_read_snapshot(|transaction| {
            load_route_grant_v2_authority_in(transaction, hostname, active_signer_kid)
        })
    }

    /// Sign under the same Gateway/signer barrier and repeatable-read snapshot
    /// that revalidates every Route authority row.
    pub(crate) fn issue_route_grant_v2_for_gateway(
        &self,
        hostname: &Hostname,
        principal: &AuthenticatedGatewayPrincipal,
        signer_binding: &RouteGrantV2SignerBinding,
        signer: &RouteGrantV2Signer,
        // Transitional caller argument only; deliberately not authority.
        _legacy_active_guest_digest: &Sha256Digest,
        request: &AuthorityRequestContext,
    ) -> Result<RouteGrantV2MachineAuthorityLoad> {
        self.authority_request_route_v2_read_snapshot(request, |transaction| {
            lock_route_v2_machine_authority_shared(transaction)?;
            let Some(scope) = revalidate_gateway_principal_current_in(transaction, principal)?
            else {
                return Ok(RouteGrantV2MachineAuthorityLoad::AuthenticationFailed);
            };
            let Some(hostname_workspace_id) =
                load_hostname_scope_workspace_in(transaction, hostname)?
            else {
                return Ok(RouteGrantV2MachineAuthorityLoad::Rejected(
                    RouteGrantV2AuthorityRejection::NotFound,
                ));
            };
            if !scope.authorizes_workspace(&hostname_workspace_id) {
                return Ok(RouteGrantV2MachineAuthorityLoad::AuthenticationFailed);
            }
            let endpoint_id =
                load_hostname_scope_endpoint_in(transaction, hostname)?.ok_or_else(corrupt)?;
            let endpoint_workspace_id =
                load_endpoint_scope_workspace_in(transaction, &endpoint_id)?.ok_or_else(corrupt)?;
            if !scope.authorizes_workspace(&endpoint_workspace_id) {
                return Ok(RouteGrantV2MachineAuthorityLoad::AuthenticationFailed);
            }
            if signer_binding.active_kid() != Some(signer.kid()) {
                return Ok(RouteGrantV2MachineAuthorityLoad::SignerUnavailable);
            }
            let signer_is_current =
                match route_grant_v2_signer_is_current_in(transaction, signer_binding) {
                    Ok(current) => current,
                    Err(AuthorityTransactionError::Domain(AuthorityError::BackendUnknown)) => {
                        return Ok(RouteGrantV2MachineAuthorityLoad::SignerUnavailable);
                    }
                    Err(error) => return Err(error),
                };
            if !signer_is_current {
                return Ok(RouteGrantV2MachineAuthorityLoad::SignerUnavailable);
            }
            let endpoint =
                load_current_endpoint_by_hostname_in(transaction, hostname)?.ok_or_else(corrupt)?;
            if endpoint.endpoint_id != endpoint_id
                || endpoint.workspace_id != hostname_workspace_id
                || endpoint.workspace_id != endpoint_workspace_id
            {
                return Err(corrupt());
            }
            let snapshot = match load_route_grant_v2_authority_from_locator_in(
                transaction,
                signer_binding,
                signer.kid(),
                RouteGrantV2AuthorityLocator { endpoint },
            )? {
                RouteGrantV2AuthorityLoad::Ready(snapshot) => snapshot,
                RouteGrantV2AuthorityLoad::Rejected(rejection) => {
                    return Ok(RouteGrantV2MachineAuthorityLoad::Rejected(rejection));
                }
            };
            let issued = signer
                .issue(&snapshot, &principal.public_key_spki_sha256)
                .map_err(|_| {
                    AuthorityTransactionError::Application(ApiError::unavailable(
                        "Route Grant v2 signer could not issue from the current snapshot",
                    ))
                })?;
            Ok(RouteGrantV2MachineAuthorityLoad::Ready { snapshot, issued })
        })
    }
}

fn load_hostname_scope_workspace_in(
    transaction: &mut postgres::Transaction<'_>,
    hostname: &Hostname,
) -> AuthorityTxResult<Option<Id>> {
    transaction
        .query_opt(
            "SELECT workspace_id FROM hostname_endpoint_lookups WHERE hostname=$1",
            &[&hostname.as_str()],
        )?
        .map(|row| parse_id(row.try_get("workspace_id")?))
        .transpose()
}

fn load_hostname_scope_endpoint_in(
    transaction: &mut postgres::Transaction<'_>,
    hostname: &Hostname,
) -> AuthorityTxResult<Option<Id>> {
    transaction
        .query_opt(
            "SELECT endpoint_id FROM hostname_endpoint_lookups WHERE hostname=$1",
            &[&hostname.as_str()],
        )?
        .map(|row| parse_id(row.try_get("endpoint_id")?))
        .transpose()
}

fn load_endpoint_scope_workspace_in(
    transaction: &mut postgres::Transaction<'_>,
    endpoint_id: &Id,
) -> AuthorityTxResult<Option<Id>> {
    transaction
        .query_opt(
            "SELECT workspace_id FROM endpoint_records WHERE endpoint_id=$1",
            &[&endpoint_id.as_str()],
        )?
        .map(|row| parse_id(row.try_get("workspace_id")?))
        .transpose()
}

#[cfg(test)]
fn load_route_grant_v2_authority_in(
    transaction: &mut postgres::Transaction<'_>,
    hostname: &Hostname,
    active_signer_kid: &KeyId,
) -> AuthorityTxResult<RouteGrantV2AuthorityLoad> {
    let Some(endpoint) = load_current_endpoint_by_hostname_in(transaction, hostname)? else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::NotFound,
        ));
    };
    let Some(signer_binding) = load_current_signer(transaction, "")? else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    };
    if signer_binding.active_kid() != Some(active_signer_kid) {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    }
    load_route_grant_v2_authority_from_locator_in(
        transaction,
        &signer_binding,
        active_signer_kid,
        RouteGrantV2AuthorityLocator { endpoint },
    )
}

fn load_route_grant_v2_authority_from_locator_in(
    transaction: &mut postgres::Transaction<'_>,
    signer_binding: &RouteGrantV2SignerBinding,
    active_signer_kid: &KeyId,
    locator: RouteGrantV2AuthorityLocator,
) -> AuthorityTxResult<RouteGrantV2AuthorityLoad> {
    let endpoint = locator.endpoint;
    let lifecycle = load_lifecycle_route_authority_snapshot_in(
        transaction,
        &endpoint.workspace_id,
        &endpoint.cat_id,
    )?
    .ok_or_else(corrupt)?;

    if lifecycle.deleted_at.is_some() {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Gone,
        ));
    }
    if lifecycle.unresolved_leaves_running {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Pending,
        ));
    }
    if lifecycle.stable_state != Some(LifecycleStableState::Running) {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::RunRequired,
        ));
    }
    let Some(serving_operation_id) = endpoint.effective_serving_operation_id.as_ref() else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Pending,
        ));
    };
    let serving_operation =
        load_route_operation_in(transaction, serving_operation_id)?.ok_or_else(corrupt)?;
    let Some(placement) = lifecycle.current_placement.as_ref() else {
        return Err(corrupt());
    };
    let Some(current_session) = load_current_session_unlocked(transaction, &placement.node_id)?
    else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    };
    let Some(inventory) = load_runtime_full_inventory_unlocked(transaction, &placement.node_id)?
    else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    };
    let Some(ring_ack) = load_route_ring_ack_in(transaction, &placement.node_id)? else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    };
    let Some((transport_identity, node_transport_target)) =
        load_node_transport_authority_in(transaction, &placement.node_id)?
    else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    };
    if transport_identity.node_id != placement.node_id {
        return Err(corrupt());
    }
    let evaluated_at_unix_ms = database_now(transaction)?;
    evaluate_atomic_route_signer(AtomicRouteSignerFacts {
        endpoint: &endpoint,
        lifecycle: &lifecycle,
        serving_operation: &serving_operation,
        current_session: &current_session,
        inventory: &inventory,
        ring_ack: &ring_ack,
        signer_binding,
        active_signer_kid,
        node_transport_target,
        evaluated_at_unix_ms,
    })
}

fn evaluate_atomic_route_signer(
    facts: AtomicRouteSignerFacts<'_>,
) -> AuthorityTxResult<RouteGrantV2AuthorityLoad> {
    let AtomicRouteSignerFacts {
        endpoint,
        lifecycle,
        serving_operation,
        current_session,
        inventory,
        ring_ack,
        signer_binding,
        active_signer_kid,
        node_transport_target,
        evaluated_at_unix_ms,
    } = facts;
    if lifecycle.workspace_id != endpoint.workspace_id || lifecycle.cat_id != endpoint.cat_id {
        return Err(corrupt());
    }
    let Some(ready) = lifecycle.effective_runtime_ready.as_ref() else {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Pending,
        ));
    };
    let Some(placement) = lifecycle.current_placement.as_ref() else {
        return Err(corrupt());
    };
    if ready.evidence.runtime_config_digest != lifecycle.current_runtime_config_digest
        || ready.source_operation.operation_id != ready.evidence.source_lifecycle_operation_id
        || ready.source_operation.placement_identity != *placement
    {
        return Err(corrupt());
    }
    let current_session_binding = session_binding(current_session);
    if current_session_binding.node_id != placement.node_id
        || evaluated_at_unix_ms >= current_session.lease_deadline_unix_ms
    {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    }
    if inventory.attestation.session != current_session_binding
        || !inventory_attestation_is_fresh(&inventory.attestation, evaluated_at_unix_ms)
    {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    }
    let signer_reference = signer_binding.reference();
    if signer_binding.active_kid() != Some(active_signer_kid)
        || ring_ack.ack.session != current_session_binding
        || ring_ack.accepted_at_unix_ms > evaluated_at_unix_ms
        || ring_ack.ack.ring_version != signer_reference.public_key_ring_version
        || ring_ack.ack.key_ring_digest != signer_reference.public_key_ring_digest
        || !ring_ack
            .ack
            .loaded_kids
            .iter()
            .any(|kid| kid == active_signer_kid)
        || key_ring_digest(ring_ack.ack.ring_version, &ring_ack.ack.loaded_kids)
            .map_err(|_| corrupt())?
            != ring_ack.ack.key_ring_digest
    {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Unavailable,
        ));
    }
    let RouteOperationState::Terminal { terminal } = &serving_operation.state else {
        return Err(corrupt());
    };
    let RouteOperationTerminal::NodeResult { response, .. } = terminal.as_ref() else {
        return Err(corrupt());
    };
    if !matches!(response.result, RouteNodeResult::Serving(_)) {
        return Err(corrupt());
    }
    let expected_binding = RouteServingBinding {
        workspace_id: endpoint.workspace_id.clone(),
        endpoint_id: endpoint.endpoint_id.clone(),
        hostname: endpoint.hostname.clone(),
        cat_id: endpoint.cat_id.clone(),
        placement_identity: placement.clone(),
        effective_runtime_ready: ready.evidence.clone(),
        route_epoch: endpoint.route_epoch,
        admission_session: current_session_binding,
        protocol: endpoint.protocol,
        target_port: endpoint.target_port,
    };
    if serving_operation.operation_id
        != *endpoint
            .effective_serving_operation_id
            .as_ref()
            .ok_or_else(corrupt)?
        || response.result.binding() != &expected_binding
    {
        return Ok(RouteGrantV2AuthorityLoad::Rejected(
            RouteGrantV2AuthorityRejection::Pending,
        ));
    }

    Ok(RouteGrantV2AuthorityLoad::Ready(Box::new(
        RouteGrantV2AuthoritySnapshot {
            workspace_id: endpoint.workspace_id.clone(),
            endpoint_id: endpoint.endpoint_id.clone(),
            hostname: endpoint.hostname.clone(),
            cat_id: endpoint.cat_id.clone(),
            node_id: placement.node_id.clone(),
            runtime_incarnation: ready.evidence.runtime_incarnation.clone(),
            route_epoch: endpoint.route_epoch,
            protocol: endpoint.protocol,
            target_port: endpoint.target_port,
            node_transport_target,
            evaluated_at_unix_ms,
        },
    )))
}

fn inventory_attestation_is_fresh(
    attestation: &RuntimeInventoryAttestation,
    evaluated_at_unix_ms: UnixMillis,
) -> bool {
    let accepted = attestation.accepted_at_unix_ms.get();
    let now = evaluated_at_unix_ms.get();
    accepted <= now
        && accepted
            .checked_add(PLACEMENT_INVENTORY_MAX_AGE_MS)
            .is_some_and(|expires| now < expires)
}

fn load_current_endpoint_by_hostname_in(
    transaction: &mut postgres::Transaction<'_>,
    hostname: &Hostname,
) -> AuthorityTxResult<Option<CurrentEndpointRouteBinding>> {
    transaction
        .query_opt(
            "SELECT e.workspace_id, e.cat_id, e.endpoint_id,
                    e.binding_state, e.hostname, e.protocol, e.target_port,
                    e.route_epoch, e.effective_serving_operation_id,
                    l.workspace_id AS lookup_workspace_id,
                    l.cat_id AS lookup_cat_id,
                    l.endpoint_id AS lookup_endpoint_id
               FROM hostname_endpoint_lookups l
               JOIN endpoint_records e
                 ON e.workspace_id=l.workspace_id
                AND e.cat_id=l.cat_id
                AND e.endpoint_id=l.endpoint_id
                AND e.hostname=l.hostname
              WHERE l.hostname=$1",
            &[&hostname.as_str()],
        )?
        .map(|row| decode_current_endpoint(&row, hostname))
        .transpose()
}

fn decode_current_endpoint(
    row: &Row,
    expected_hostname: &Hostname,
) -> AuthorityTxResult<CurrentEndpointRouteBinding> {
    let workspace_id = parse_id(row.try_get("workspace_id")?)?;
    let cat_id = parse_id(row.try_get("cat_id")?)?;
    let endpoint_id = parse_id(row.try_get("endpoint_id")?)?;
    let hostname = parse_hostname(row.try_get("hostname")?)?;
    let protocol = parse_protocol(&row.try_get::<_, String>("protocol")?)?;
    let port: i32 = row.try_get("target_port")?;
    let target_port = u16::try_from(port).map_err(|_| corrupt())?;
    let route_epoch = Epoch::from_pg(row.try_get("route_epoch")?).map_err(|_| corrupt())?;
    let effective_serving_operation_id = row
        .try_get::<_, Option<String>>("effective_serving_operation_id")?
        .map(parse_id)
        .transpose()?;
    if row.try_get::<_, String>("binding_state")? != "bound"
        || hostname != *expected_hostname
        || workspace_id != parse_id(row.try_get("lookup_workspace_id")?)?
        || cat_id != parse_id(row.try_get("lookup_cat_id")?)?
        || endpoint_id != parse_id(row.try_get("lookup_endpoint_id")?)?
        || target_port == 0
    {
        return Err(corrupt());
    }
    Ok(CurrentEndpointRouteBinding {
        workspace_id,
        cat_id,
        endpoint_id,
        hostname,
        protocol,
        target_port,
        route_epoch,
        effective_serving_operation_id,
    })
}

fn load_route_operation_in(
    transaction: &mut postgres::Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<Option<RouteOperation>> {
    transaction
        .query_opt(
            "SELECT operation_id, workspace_id, cat_id, endpoint_id,
                    operation_kind, canonical_request_bytes,
                    canonical_request_sha256,
                    expected_predecessor_operation_id,
                    expected_predecessor_result_kind,
                    expected_predecessor_result_sha256,
                    hostname, protocol, target_port, route_epoch,
                    source_lifecycle_operation_id, runtime_incarnation,
                    node_id, placement_epoch, node_boot_id,
                    agent_instance_id, admission_session_epoch,
                    state, terminal_source, terminal_result_kind,
                    canonical_result_bytes, canonical_result_sha256,
                    created_at_unix_ms, terminal_at_unix_ms
               FROM route_operations WHERE operation_id=$1",
            &[&operation_id.as_str()],
        )?
        .map(|row| decode_route_operation_row(&row))
        .transpose()
}

pub(super) fn decode_route_operation_row(row: &Row) -> AuthorityTxResult<RouteOperation> {
    let exact_request: Vec<u8> = row.try_get("canonical_request_bytes")?;
    let request = decode_route_command_envelope(&exact_request).map_err(|_| corrupt())?;
    let operation_id = parse_id(row.try_get("operation_id")?)?;
    let endpoint_id = parse_id(row.try_get("endpoint_id")?)?;
    let created_at_unix_ms =
        UnixMillis::from_pg(row.try_get("created_at_unix_ms")?).map_err(|_| corrupt())?;
    let terminal_at_unix_ms = row
        .try_get::<_, Option<i64>>("terminal_at_unix_ms")?
        .map(UnixMillis::from_pg)
        .transpose()
        .map_err(|_| corrupt())?;
    let state = match row.try_get::<_, String>("state")?.as_str() {
        "unresolved" => RouteOperationState::Unresolved,
        "terminal" => {
            let terminal_source = row
                .try_get::<_, Option<String>>("terminal_source")?
                .ok_or_else(corrupt)?;
            let result_bytes = row
                .try_get::<_, Option<Vec<u8>>>("canonical_result_bytes")?
                .ok_or_else(corrupt)?;
            let result_digest = parse_digest(
                row.try_get::<_, Option<String>>("canonical_result_sha256")?
                    .ok_or_else(corrupt)?,
            )?;
            let terminal = match terminal_source.as_str() {
                "node_result" => {
                    let response =
                        decode_route_command_response(&result_bytes).map_err(|_| corrupt())?;
                    if route_terminal_result_digest(&response).map_err(|_| corrupt())?
                        != result_digest
                    {
                        return Err(corrupt());
                    }
                    RouteOperationTerminal::NodeResult {
                        response: Box::new(response),
                        terminal_result_digest: result_digest,
                    }
                }
                "control_invalidation" => {
                    let invalidation =
                        decode_route_control_invalidation(&result_bytes).map_err(|_| corrupt())?;
                    if invalidation.invalidation_digest != result_digest {
                        return Err(corrupt());
                    }
                    RouteOperationTerminal::ControlInvalidation {
                        invalidation: Box::new(invalidation),
                    }
                }
                _ => return Err(corrupt()),
            };
            RouteOperationState::Terminal {
                terminal: Box::new(terminal),
            }
        }
        _ => return Err(corrupt()),
    };
    let operation = RouteOperation {
        version: request.version,
        operation_id: operation_id.clone(),
        endpoint_id: endpoint_id.clone(),
        command_kind: request.command_kind(),
        canonical_request: Box::new(request.clone()),
        request_fingerprint: request.request_fingerprint.clone(),
        state,
        created_at_unix_ms,
        terminal_at_unix_ms,
    };
    validate_route_operation(&operation).map_err(|_| corrupt())?;
    validate_route_operation_projections(row, &operation, &exact_request)?;
    Ok(operation)
}

fn validate_route_operation_projections(
    row: &Row,
    operation: &RouteOperation,
    exact_request: &[u8],
) -> AuthorityTxResult<()> {
    let request = operation.canonical_request.as_ref();
    let binding = &request.binding;
    let (predecessor_id, predecessor_kind, predecessor_digest) = match &request.predecessor {
        RouteCommandPredecessor::Genesis => (None, None, None),
        RouteCommandPredecessor::Exact {
            operation_id,
            terminal_result_kind,
            terminal_result_digest,
        } => (
            Some(operation_id.as_str()),
            Some(terminal_kind_text(*terminal_result_kind)),
            Some(terminal_result_digest.as_str()),
        ),
    };
    let expected_result_kind = match &operation.state {
        RouteOperationState::Unresolved => None,
        RouteOperationState::Terminal { terminal } => Some(terminal_kind_text(terminal.kind())),
    };
    let exact_result_bytes = match &operation.state {
        RouteOperationState::Unresolved => None,
        RouteOperationState::Terminal { terminal } => match terminal.as_ref() {
            RouteOperationTerminal::NodeResult { response, .. } => {
                Some(encode_route_command_response(response).map_err(|_| corrupt())?)
            }
            RouteOperationTerminal::ControlInvalidation { invalidation } => {
                Some(encode_route_control_invalidation(invalidation).map_err(|_| corrupt())?)
            }
        },
    };
    if row.try_get::<_, String>("operation_id")? != operation.operation_id.as_str()
        || row.try_get::<_, String>("workspace_id")? != binding.workspace_id.as_str()
        || row.try_get::<_, String>("cat_id")? != binding.cat_id.as_str()
        || row.try_get::<_, String>("endpoint_id")? != operation.endpoint_id.as_str()
        || row.try_get::<_, String>("operation_kind")? != command_kind_text(request.command)
        || row.try_get::<_, Vec<u8>>("canonical_request_bytes")? != exact_request
        || row.try_get::<_, String>("canonical_request_sha256")?
            != operation.request_fingerprint.as_str()
        || row
            .try_get::<_, Option<String>>("expected_predecessor_operation_id")?
            .as_deref()
            != predecessor_id
        || row
            .try_get::<_, Option<String>>("expected_predecessor_result_kind")?
            .as_deref()
            != predecessor_kind
        || row
            .try_get::<_, Option<String>>("expected_predecessor_result_sha256")?
            .as_deref()
            != predecessor_digest
        || row.try_get::<_, String>("hostname")? != binding.hostname.as_str()
        || row.try_get::<_, String>("protocol")? != protocol_text(binding.protocol)
        || row.try_get::<_, i32>("target_port")? != i32::from(binding.target_port)
        || Epoch::from_pg(row.try_get("route_epoch")?).map_err(|_| corrupt())?
            != binding.route_epoch
        || row.try_get::<_, String>("source_lifecycle_operation_id")?
            != binding
                .effective_runtime_ready
                .source_lifecycle_operation_id
                .as_str()
        || row.try_get::<_, String>("runtime_incarnation")?
            != binding.effective_runtime_ready.runtime_incarnation.as_str()
        || row.try_get::<_, String>("node_id")? != binding.placement_identity.node_id.as_str()
        || Epoch::from_pg(row.try_get("placement_epoch")?).map_err(|_| corrupt())?
            != binding.placement_identity.placement_epoch
        || row.try_get::<_, String>("node_boot_id")?
            != binding.admission_session.node_boot_id.as_str()
        || row.try_get::<_, String>("agent_instance_id")?
            != binding.admission_session.agent_instance_id.as_str()
        || Epoch::from_pg(row.try_get("admission_session_epoch")?).map_err(|_| corrupt())?
            != binding.admission_session.agent_session_epoch
        || row
            .try_get::<_, Option<String>>("terminal_result_kind")?
            .as_deref()
            != expected_result_kind
        || row.try_get::<_, Option<Vec<u8>>>("canonical_result_bytes")? != exact_result_bytes
    {
        return Err(corrupt());
    }
    Ok(())
}

pub(super) fn load_route_ring_ack_in(
    transaction: &mut postgres::Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<StoredRouteRingAck>> {
    transaction
        .query_opt(
            "SELECT canonical_ack_bytes, canonical_ack_sha256, ack_id,
                    ack_sequence, node_id, node_boot_id, agent_instance_id,
                    admission_session_epoch, ring_version, key_ring_digest,
                    loaded_kids::text AS loaded_kids_json,
                    accepted_at_unix_ms
               FROM route_node_ring_acks WHERE node_id=$1",
            &[&node_id.as_str()],
        )?
        .map(|row| decode_route_ring_ack_row(&row))
        .transpose()
}

fn decode_route_ring_ack_row(row: &Row) -> AuthorityTxResult<StoredRouteRingAck> {
    let ack = decode_route_node_ring_ack(&row.try_get::<_, Vec<u8>>("canonical_ack_bytes")?)
        .map_err(|_| corrupt())?;
    let loaded_kids: Vec<KeyId> =
        serde_json::from_str(&row.try_get::<_, String>("loaded_kids_json")?)
            .map_err(|_| corrupt())?;
    let accepted_at_unix_ms =
        UnixMillis::from_pg(row.try_get("accepted_at_unix_ms")?).map_err(|_| corrupt())?;
    if row.try_get::<_, String>("canonical_ack_sha256")? != ack.ack_digest.as_str()
        || row.try_get::<_, String>("ack_id")? != ack.ack_id.as_str()
        || Sequence::from_pg(row.try_get("ack_sequence")?).map_err(|_| corrupt())?
            != ack.ack_sequence
        || row.try_get::<_, String>("node_id")? != ack.session.node_id.as_str()
        || row.try_get::<_, String>("node_boot_id")? != ack.session.node_boot_id.as_str()
        || row.try_get::<_, String>("agent_instance_id")? != ack.session.agent_instance_id.as_str()
        || Epoch::from_pg(row.try_get("admission_session_epoch")?).map_err(|_| corrupt())?
            != ack.session.agent_session_epoch
        || Epoch::from_pg(row.try_get("ring_version")?).map_err(|_| corrupt())? != ack.ring_version
        || row.try_get::<_, String>("key_ring_digest")? != ack.key_ring_digest.as_str()
        || loaded_kids != ack.loaded_kids
    {
        return Err(corrupt());
    }
    Ok(StoredRouteRingAck {
        ack,
        accepted_at_unix_ms,
    })
}

fn load_node_transport_authority_in(
    transaction: &mut postgres::Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<
    Option<(
        cats_api::runtime_reconciliation::NodeIdentity,
        NodeTransportTarget,
    )>,
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

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

const fn command_kind_text(command: RouteCommand) -> &'static str {
    match command {
        RouteCommand::Enable => "enable",
        RouteCommand::Disable => "disable",
    }
}

const fn terminal_kind_text(kind: RouteTerminalResultKind) -> &'static str {
    match kind {
        RouteTerminalResultKind::Serving => "serving",
        RouteTerminalResultKind::Closed => "closed",
        RouteTerminalResultKind::Rejected => "rejected",
        RouteTerminalResultKind::Invalidated => "invalidated",
    }
}

const fn protocol_text(protocol: HttpProtocol) -> &'static str {
    match protocol {
        HttpProtocol::Http => "http",
    }
}

fn parse_protocol(value: &str) -> AuthorityTxResult<HttpProtocol> {
    match value {
        "http" => Ok(HttpProtocol::Http),
        _ => Err(corrupt()),
    }
}

fn parse_id(value: String) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(corrupt)
}

fn parse_hostname(value: String) -> AuthorityTxResult<Hostname> {
    Hostname::new(value).ok_or_else(corrupt)
}

fn parse_digest(value: String) -> AuthorityTxResult<Sha256Digest> {
    Sha256Digest::new(value).ok_or_else(corrupt)
}

fn corrupt() -> AuthorityTransactionError {
    AuthorityError::BackendUnknown.into()
}

#[cfg(test)]
mod atomic_signer_tests {
    use super::*;
    use cats_api::runtime_reconciliation::{ContractVersion, NodeBootId};

    #[test]
    fn inventory_freshness_uses_the_strict_right_boundary() {
        let attestation = attestation(10);
        assert!(inventory_attestation_is_fresh(
            &attestation,
            UnixMillis::new(10 + PLACEMENT_INVENTORY_MAX_AGE_MS - 1).unwrap()
        ));
        assert!(!inventory_attestation_is_fresh(
            &attestation,
            UnixMillis::new(10 + PLACEMENT_INVENTORY_MAX_AGE_MS).unwrap()
        ));
    }

    #[test]
    fn future_inventory_attestation_is_not_fresh() {
        assert!(!inventory_attestation_is_fresh(
            &attestation(11),
            UnixMillis::new(10).unwrap()
        ));
    }

    fn attestation(accepted_at: u64) -> RuntimeInventoryAttestation {
        RuntimeInventoryAttestation {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: id("node_a"),
                node_boot_id: NodeBootId::new("ab".repeat(16)).unwrap(),
                agent_instance_id: random(1),
                agent_session_epoch: epoch(1),
            },
            inventory_epoch: epoch(1),
            scan_id: random(2),
            inventory_digest: digest(3),
            source_report_id: random(4),
            source_sequence: Sequence::new(1).unwrap(),
            accepted_at_unix_ms: UnixMillis::new(accepted_at).unwrap(),
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value.to_owned()).unwrap()
    }

    fn random(value: u8) -> RandomId128 {
        RandomId128::new(format!("{value:02x}").repeat(16)).unwrap()
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).unwrap()
    }
}
