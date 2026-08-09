//! PostgreSQL core for the A20 Desired/inventory/observation spine.
//!
//! Authentication framing deliberately stays in F3b. Every entry here starts
//! from the narrow authenticated credential produced by that adapter and
//! binds it to the one provisioned identity and current AgentSession inside
//! the same transaction that reads or changes runtime authority.

use std::collections::{BTreeMap, BTreeSet};

use cats_api::runtime_reconciliation::{
    decode_admission_inventory_attestation, decode_desired_read_snapshot, decode_node_observation,
    decode_observation_acceptance, encode_admission_inventory_attestation,
    encode_desired_read_request, encode_desired_read_snapshot, encode_node_observation,
    encode_observation_acceptance, AdmissionInventoryAttestation, AgentSession,
    AppliedDesiredEvidence, AssignedKind, AssignedPlacement, AssignedSetLimit, Condition,
    ContractError, ContractErrorDetail, ContractName, ContractVersion, CredentialBinding,
    DesiredReadRequest, DesiredReadSnapshot, DesiredRuntimeSpec, Epoch, Id, JsonPointer,
    LifecycleAdmission, LocalLineageState, MalformedProblem, NodeIdentity, NodeIdentityState,
    NodeObservation, ObservationAcceptance, ObservationInventoryAcceptance, ObservedDiskKind,
    ObservedRuntimeStatus, Operation, OperationFailure, OperationPhase, OperationSuccess,
    OperationTerminal, OwnershipTokenEvidence, PreconditionFailureReason, ProcessRole,
    ProcessState, RandomId128, ReadyReason, ReconcileStep, Revision, RouteGateState, RuntimeTarget,
    Sequence, SessionBinding, StableState, UnixMillis, VolumeAuthorityEvidence, WireU64,
    DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES,
};
use cats_storage::authority::{DeleteCompletionReceipt, VolumeAdminState, VolumeDurability};
use postgres::{Row, Transaction};

use super::pg_codec::PgBigInt;
use super::product::{DiskAdminState, DiskRole};
use super::product_rows::{
    load_assigned_desired_for_update, load_assigned_desired_unlocked, load_desired_for_update,
    load_disk_by_id_for_update, load_pending_operation_by_cat_for_update, update_operation,
};
use super::rows::{database_now, load_delete_completion_for_update, load_volume_for_update};
use crate::store::agent_sessions::{
    load_current_session_for_update, load_current_session_unlocked,
    load_identity_by_credential_for_update, load_identity_by_node_for_update,
    load_identity_by_node_unlocked, load_provisioned_identities_after,
    renew_current_session_deadline, AuthenticatedNodeCredential, PROVISIONED_NODE_ID_PAGE_SIZE,
};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{Result, Store};

pub(crate) const AGENT_SESSION_LEASE_MS: u64 = 60_000;
pub(crate) const DESIRED_READ_TTL_MS: u64 = 30_000;
pub(crate) const PLACEMENT_INVENTORY_MAX_AGE_MS: u64 = 60_000;
pub(crate) const ROUTE_CAT_OBSERVATION_MAX_AGE_MS: u64 = 30_000;
pub(crate) const MAX_ASSIGNED_SPECS: usize = 1024;

/// One process-local planner page. The page size bounds each authority read;
/// it is not a fleet-size, persisted, or wire-protocol limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvisionedNodeIdPage {
    pub(crate) node_ids: Vec<Id>,
    pub(crate) next_after: Option<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeSpineOutcome<T> {
    Accepted(T),
    Rejected(RuntimeSpineRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeSpineRejection {
    IdentityNotEligible,
    Contract(ContractError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlacementAdmissionSnapshot {
    pub(crate) evaluated_at_unix_ms: UnixMillis,
    pub(crate) node_identity: NodeIdentity,
    pub(crate) agent_session: AgentSession,
    pub(crate) inventory_attestation: AdmissionInventoryAttestation,
    pub(crate) full_inventory_observation: NodeObservation,
    pub(crate) assigned_desired_specs: Vec<DesiredRuntimeSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlacementAdmissionRejection {
    IdentityNotProvisioned,
    SessionMissing,
    SessionExpired,
    GuestConfigMismatch,
    InventoryMissing,
    InventoryStale,
    InventorySessionReplaced,
    AssignedSetChanged,
    AdmissionChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlacementAdmissionLoad {
    Accepted(Box<PlacementAdmissionSnapshot>),
    Rejected(PlacementAdmissionRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteRuntimeSnapshot {
    pub(crate) admission: PlacementAdmissionSnapshot,
    pub(crate) runtime: ObservedRuntimeStatus,
    pub(crate) source_observation_id: RandomId128,
    pub(crate) source_heartbeat_sequence: Sequence,
    pub(crate) runtime_accepted_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteRuntimeRejection {
    Admission(PlacementAdmissionRejection),
    RuntimeMissing,
    RuntimeStale,
    RuntimeSessionReplaced,
    RuntimeInventoryEpochChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteRuntimeLoad {
    Accepted(Box<RouteRuntimeSnapshot>),
    Rejected(RouteRuntimeRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredReadState {
    response: DesiredReadSnapshot,
    consumed_by: Option<(RandomId128, Sequence)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservationReceiveState {
    observation: NodeObservation,
    acceptance: ObservationAcceptance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdmissionInventoryState {
    attestation: AdmissionInventoryAttestation,
    full_observation: NodeObservation,
    assigned_snapshot: DesiredReadSnapshot,
}

/// Context validation has two deliberately separate failure channels: a
/// closed wire-visible rejection and a fatal store/invariant failure. Keeping
/// them nested prevents a normal stale cursor or epoch from escaping as a 500
/// and, just as importantly, lets the transaction return without writing.
type ContextValidation<T> = AuthorityTxResult<std::result::Result<T, ContractError>>;

impl Store {
    /// Lists one bounded, stable keyset page from NodeIdentity authority.
    ///
    /// This is only a candidate seed: callers must load and evaluate the full
    /// placement admission snapshot for every returned id. A change between
    /// pages merely invalidates that plan; the selected NodeIdentity remains
    /// the unique assigned-set coordination lock at Desired commit time.
    pub(crate) fn list_provisioned_node_ids_after(
        &self,
        after: Option<&Id>,
    ) -> Result<ProvisionedNodeIdPage> {
        self.authority_read_snapshot(|transaction| {
            let mut identities = load_provisioned_identities_after(transaction, after)?;
            let has_more = identities.len() > PROVISIONED_NODE_ID_PAGE_SIZE;
            if has_more {
                identities.truncate(PROVISIONED_NODE_ID_PAGE_SIZE);
            }
            let next_after = has_more
                .then(|| identities.last().map(|identity| identity.node_id.clone()))
                .flatten();
            Ok(ProvisionedNodeIdPage {
                node_ids: identities
                    .into_iter()
                    .map(|identity| identity.node_id)
                    .collect(),
                next_after,
            })
        })
    }

    pub(crate) fn runtime_desired_read(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &DesiredReadRequest,
    ) -> Result<RuntimeSpineOutcome<DesiredReadSnapshot>> {
        if let Err(error) = encode_desired_read_request(request) {
            return Ok(rejected(error));
        }
        self.authority_repeatable_transaction(|transaction| {
            desired_read_in(transaction, authenticated, request)
        })
    }

    pub(crate) fn runtime_accept_observation(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        observation: &NodeObservation,
    ) -> Result<RuntimeSpineOutcome<ObservationAcceptance>> {
        if let Err(error) = encode_node_observation(observation) {
            return Ok(rejected(error));
        }
        self.authority_repeatable_transaction(|transaction| {
            accept_observation_in(transaction, authenticated, observation)
        })
    }

    pub(crate) fn load_placement_admission_snapshot(
        &self,
        node_id: &Id,
        active_guest_digest: &cats_api::runtime_reconciliation::Sha256Digest,
    ) -> Result<PlacementAdmissionLoad> {
        self.authority_read_snapshot(|transaction| {
            load_placement_admission_in(transaction, node_id, active_guest_digest)
        })
    }

    pub(crate) fn load_route_runtime_snapshot(
        &self,
        node_id: &Id,
        cat_id: &Id,
        active_guest_digest: &cats_api::runtime_reconciliation::Sha256Digest,
    ) -> Result<RouteRuntimeLoad> {
        self.authority_read_snapshot(|transaction| {
            load_route_runtime_in(transaction, node_id, cat_id, active_guest_digest)
        })
    }
}

/// Acquires the one per-Node assigned-set coordination lock and revalidates
/// the exact placement facts consumed by a Desired mutation.
///
/// Callers must invoke this before locking any Volume, Disk, Desired or
/// Operation row. All Desired mutation paths use this same NodeIdentity row;
/// that closes the otherwise-unlockable absent-row/phantom window against a
/// concurrent full observation.
pub(super) fn lock_placement_admission_for_desired_mutation(
    transaction: &mut Transaction<'_>,
    planned: &PlacementAdmissionSnapshot,
    active_guest_digest: &cats_api::runtime_reconciliation::Sha256Digest,
) -> AuthorityTxResult<PlacementAdmissionLoad> {
    let Some(identity) =
        load_identity_by_node_for_update(transaction, &planned.node_identity.node_id)?
    else {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::IdentityNotProvisioned,
        ));
    };
    if identity.state != NodeIdentityState::Provisioned {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::IdentityNotProvisioned,
        ));
    }
    if identity != planned.node_identity {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::AdmissionChanged,
        ));
    }
    let current = match load_placement_admission_in(
        transaction,
        &planned.node_identity.node_id,
        active_guest_digest,
    )? {
        PlacementAdmissionLoad::Accepted(snapshot) => *snapshot,
        rejection @ PlacementAdmissionLoad::Rejected(_) => return Ok(rejection),
    };
    let same_session = current.agent_session.version == planned.agent_session.version
        && current.agent_session.node_id == planned.agent_session.node_id
        && current.agent_session.immutable_host_id == planned.agent_session.immutable_host_id
        && current.agent_session.node_boot_id == planned.agent_session.node_boot_id
        && current.agent_session.agent_instance_id == planned.agent_session.agent_instance_id
        && current.agent_session.agent_session_epoch == planned.agent_session.agent_session_epoch
        && current.agent_session.registration_attempt_id
            == planned.agent_session.registration_attempt_id
        && current.agent_session.guest_config_digest == planned.agent_session.guest_config_digest
        && current.agent_session.lease_deadline_unix_ms
            >= planned.agent_session.lease_deadline_unix_ms;
    if current.node_identity != planned.node_identity
        || !same_session
        || current.inventory_attestation != planned.inventory_attestation
        || current.full_inventory_observation != planned.full_inventory_observation
        || current.assigned_desired_specs != planned.assigned_desired_specs
    {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::AdmissionChanged,
        ));
    }
    Ok(PlacementAdmissionLoad::Accepted(Box::new(current)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationSourceKind {
    Full,
    Partial,
}

struct CurrentCatObservation {
    runtime: ObservedRuntimeStatus,
    session: SessionBinding,
    inventory_epoch: Epoch,
    source_observation_id: RandomId128,
    heartbeat_sequence: Sequence,
    accepted_at_unix_ms: UnixMillis,
    source_kind: ObservationSourceKind,
}

fn load_route_runtime_in(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    cat_id: &Id,
    active_guest_digest: &cats_api::runtime_reconciliation::Sha256Digest,
) -> AuthorityTxResult<RouteRuntimeLoad> {
    let admission = match load_placement_admission_in(transaction, node_id, active_guest_digest)? {
        PlacementAdmissionLoad::Accepted(snapshot) => *snapshot,
        PlacementAdmissionLoad::Rejected(reason) => {
            return Ok(RouteRuntimeLoad::Rejected(
                RouteRuntimeRejection::Admission(reason),
            ));
        }
    };
    let Some(current) = load_current_cat_observation(transaction, node_id, cat_id)? else {
        return Ok(RouteRuntimeLoad::Rejected(
            RouteRuntimeRejection::RuntimeMissing,
        ));
    };
    let expected_session = session_binding(&admission.agent_session);
    if current.session != expected_session {
        return Ok(RouteRuntimeLoad::Rejected(
            RouteRuntimeRejection::RuntimeSessionReplaced,
        ));
    }
    if current.inventory_epoch != admission.inventory_attestation.inventory_epoch {
        return Ok(RouteRuntimeLoad::Rejected(
            RouteRuntimeRejection::RuntimeInventoryEpochChanged,
        ));
    }
    if current.accepted_at_unix_ms > admission.evaluated_at_unix_ms {
        return Err(corrupt(
            "database time moved behind current Cat observation",
        ));
    }
    let stale_at = checked_add_time(
        current.accepted_at_unix_ms,
        ROUTE_CAT_OBSERVATION_MAX_AGE_MS,
        "route runtime freshness overflow",
    )?;
    if admission.evaluated_at_unix_ms >= stale_at {
        return Ok(RouteRuntimeLoad::Rejected(
            RouteRuntimeRejection::RuntimeStale,
        ));
    }
    match current.source_kind {
        ObservationSourceKind::Full => {
            let stored = admission
                .full_inventory_observation
                .runtimes
                .iter()
                .find(|runtime| runtime.cat_id == *cat_id)
                .ok_or_else(|| corrupt("full per-Cat row is absent from its full inventory"))?;
            if stored != &current.runtime
                || current.source_observation_id
                    != admission.full_inventory_observation.observation_id
                || current.heartbeat_sequence
                    != admission.full_inventory_observation.heartbeat_sequence
                || current.accepted_at_unix_ms
                    != admission.inventory_attestation.accepted_at_unix_ms
            {
                return Err(corrupt("full per-Cat row/source receipt mismatch"));
            }
        }
        ObservationSourceKind::Partial => {
            let synthetic = NodeObservation {
                version: ContractVersion::V1,
                observation_id: current.source_observation_id.clone(),
                node_id: current.session.node_id.clone(),
                node_boot_id: current.session.node_boot_id.clone(),
                agent_instance_id: current.session.agent_instance_id.clone(),
                agent_session_epoch: current.session.agent_session_epoch,
                heartbeat_sequence: current.heartbeat_sequence,
                observed_at_unix_ms: current.accepted_at_unix_ms,
                complete_inventory: false,
                inventory_epoch: current.inventory_epoch,
                inventory_digest: None,
                inventory_read_position: None,
                key_ring_version: None,
                key_ring_digest: None,
                loaded_kids: Vec::new(),
                runtimes: vec![current.runtime.clone()],
                residue: Vec::new(),
            };
            encode_node_observation(&synthetic)
                .map_err(|_| corrupt("stored partial per-Cat runtime is not canonical"))?;
        }
    }
    Ok(RouteRuntimeLoad::Accepted(Box::new(RouteRuntimeSnapshot {
        admission,
        runtime: current.runtime,
        source_observation_id: current.source_observation_id,
        source_heartbeat_sequence: current.heartbeat_sequence,
        runtime_accepted_at_unix_ms: current.accepted_at_unix_ms,
    })))
}

fn load_placement_admission_in(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    active_guest_digest: &cats_api::runtime_reconciliation::Sha256Digest,
) -> AuthorityTxResult<PlacementAdmissionLoad> {
    let Some(identity) = load_identity_by_node_unlocked(transaction, node_id)? else {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::IdentityNotProvisioned,
        ));
    };
    if identity.state != NodeIdentityState::Provisioned {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::IdentityNotProvisioned,
        ));
    }
    let Some(session) = load_current_session_unlocked(transaction, node_id)? else {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::SessionMissing,
        ));
    };
    if session.node_id != identity.node_id
        || session.immutable_host_id != identity.immutable_host_id
    {
        return Err(corrupt(
            "NodeIdentity/current AgentSession binding mismatch",
        ));
    }
    let now = database_now(transaction)?;
    if now >= session.lease_deadline_unix_ms {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::SessionExpired,
        ));
    }
    if session.guest_config_digest != *active_guest_digest {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::GuestConfigMismatch,
        ));
    }
    let Some(inventory) = load_admission_inventory_state_unlocked(transaction, node_id)? else {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::InventoryMissing,
        ));
    };
    if observation_binding(&inventory.full_observation) != session_binding(&session) {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::InventorySessionReplaced,
        ));
    }
    let cursor = &inventory.assigned_snapshot;
    let accepted_at = inventory.attestation.accepted_at_unix_ms;
    if accepted_at > now {
        return Err(corrupt(
            "database time moved behind admission inventory acceptance",
        ));
    }
    let stale_at = checked_add_time(
        accepted_at,
        PLACEMENT_INVENTORY_MAX_AGE_MS,
        "admission inventory freshness overflow",
    )?;
    if now >= stale_at {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::InventoryStale,
        ));
    }
    let current_desired = load_assigned_desired_unlocked(transaction, node_id)?;
    if current_desired != cursor.desired_specs {
        return Ok(PlacementAdmissionLoad::Rejected(
            PlacementAdmissionRejection::AssignedSetChanged,
        ));
    }
    let runtimes: BTreeMap<&Id, &ObservedRuntimeStatus> = inventory
        .full_observation
        .runtimes
        .iter()
        .map(|runtime| (&runtime.cat_id, runtime))
        .collect();
    for desired in &current_desired {
        let runtime = runtimes
            .get(&desired.cat_id)
            .ok_or_else(|| corrupt("stored full inventory omitted an attested assigned Cat"))?;
        if runtime.applied_desired.as_ref() != Some(&applied_projection(desired)) {
            return Err(corrupt(
                "stored full inventory assigned runtime binding is corrupt",
            ));
        }
    }
    Ok(PlacementAdmissionLoad::Accepted(Box::new(
        PlacementAdmissionSnapshot {
            evaluated_at_unix_ms: now,
            node_identity: identity,
            agent_session: session,
            inventory_attestation: inventory.attestation,
            full_inventory_observation: inventory.full_observation,
            assigned_desired_specs: current_desired,
        },
    )))
}

fn desired_read_in(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    request: &DesiredReadRequest,
) -> AuthorityTxResult<RuntimeSpineOutcome<DesiredReadSnapshot>> {
    let Some(identity) = authenticate_identity(transaction, authenticated)? else {
        return Ok(RuntimeSpineOutcome::Rejected(
            RuntimeSpineRejection::IdentityNotEligible,
        ));
    };
    let Some(session) = load_current_session_for_update(transaction, &identity.node_id)? else {
        return Ok(rejected(detail(
            ContractErrorDetail::MissingAgentSession {
                node_id: identity.node_id,
            },
            "authenticated Node has no current AgentSession",
        )));
    };
    if let Some(error) = session_error(&session, &request.session) {
        return Ok(rejected(error));
    }

    let state = load_desired_read_state_for_update(transaction, &session.node_id)?;
    let now = database_now(transaction)?;
    if now >= session.lease_deadline_unix_ms {
        return Ok(rejected(session_expired(&session, now)));
    }
    if state
        .as_ref()
        .is_some_and(|state| now < state.response.issued_at_unix_ms)
    {
        return Err(corrupt(
            "database time moved behind retained Desired response",
        ));
    }

    let binding = session_binding(&session);
    let same_state_session = state
        .as_ref()
        .is_some_and(|state| state.response.session == binding);
    if same_state_session {
        let retained = state.as_ref().expect("same-session state exists");
        let last = retained.response.request_sequence;
        if request.request_sequence == last {
            return Ok(RuntimeSpineOutcome::Accepted(retained.response.clone()));
        }
        if request.request_sequence < last {
            return Ok(rejected(detail(
                ContractErrorDetail::StaleDesiredReadSequence {
                    node_id: session.node_id,
                    agent_session_epoch: session.agent_session_epoch,
                    presented_request_sequence: request.request_sequence,
                    last_request_sequence: last,
                },
                "Desired read sequence is stale",
            )));
        }
        let expected = checked_next(last, "Desired read request sequence exhausted")?;
        if request.request_sequence != expected {
            return Ok(rejected(wrong_desired_sequence(
                &session,
                expected,
                request.request_sequence,
            )));
        }
    } else if request.request_sequence.get() != 1 {
        return Ok(rejected(wrong_desired_sequence(
            &session,
            Sequence::new(1).expect("one is a Sequence"),
            request.request_sequence,
        )));
    }

    let desired_specs = load_assigned_desired_for_update(transaction, &session.node_id)?;
    if desired_specs.len() > MAX_ASSIGNED_SPECS {
        return Ok(rejected(assigned_limit(
            &session.node_id,
            AssignedSetLimit::DesiredSpecs,
        )));
    }
    if same_state_session {
        let retained = state.as_ref().expect("same-session state exists");
        let can_advance = retained.consumed_by.is_some()
            || now >= retained.response.expires_at_unix_ms
            || desired_specs != retained.response.desired_specs;
        if !can_advance {
            return Ok(rejected(detail(
                ContractErrorDetail::DesiredReadInProgress {
                    node_id: session.node_id,
                    agent_session_epoch: session.agent_session_epoch,
                    request_sequence: request.request_sequence,
                    read_position: retained.response.read_position,
                    expires_at_unix_ms: retained.response.expires_at_unix_ms,
                },
                "the retained Desired cursor is still in progress",
            )));
        }
    }

    let read_position = match &state {
        Some(state) => checked_next(
            state.response.read_position,
            "Desired read position high-water exhausted",
        )?,
        None => Sequence::new(1).expect("one is a Sequence"),
    };
    let expires_at_unix_ms = checked_add_time(now, DESIRED_READ_TTL_MS, "Desired read expiry")?;
    let response = DesiredReadSnapshot {
        version: ContractVersion::V1,
        session: binding,
        request_sequence: request.request_sequence,
        read_position,
        issued_at_unix_ms: now,
        expires_at_unix_ms,
        desired_specs,
    };
    match encode_desired_read_snapshot(&response) {
        Ok(bytes) if bytes.len() <= DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES => {}
        Ok(_) => {
            return Ok(rejected(assigned_limit(
                &session.node_id,
                AssignedSetLimit::WireBytes,
            )));
        }
        Err(error)
            if matches!(
                error.error.as_ref(),
                ContractErrorDetail::LimitExceeded { .. }
            ) =>
        {
            return Ok(rejected(assigned_limit(
                &session.node_id,
                AssignedSetLimit::WireBytes,
            )));
        }
        Err(error) => return Err(corrupt(error)),
    }
    upsert_desired_read_state(
        transaction,
        &DesiredReadState {
            response: response.clone(),
            consumed_by: None,
        },
    )?;
    Ok(RuntimeSpineOutcome::Accepted(response))
}

fn authenticate_identity(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
) -> AuthorityTxResult<Option<NodeIdentity>> {
    // This row is also the one per-Node assigned-set coordination lock.
    // Every Desired mutation must take the same NodeIdentity lock before any
    // Volume/Disk/Desired row, so an absent Desired cannot appear as a phantom
    // between cursor comparison and observation commit.
    let Some(identity) =
        load_identity_by_credential_for_update(transaction, authenticated.credential_id())?
    else {
        return Ok(None);
    };
    if identity.state != NodeIdentityState::Provisioned
        || identity.credential_id != *authenticated.credential_id()
        || identity.credential_binding != *authenticated.binding()
        || !matches!(
            identity.credential_binding,
            CredentialBinding::PublicKey { .. }
        )
    {
        return Ok(None);
    }
    Ok(Some(identity))
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn observation_binding(observation: &NodeObservation) -> SessionBinding {
    SessionBinding {
        node_id: observation.node_id.clone(),
        node_boot_id: observation.node_boot_id.clone(),
        agent_instance_id: observation.agent_instance_id.clone(),
        agent_session_epoch: observation.agent_session_epoch,
    }
}

fn session_error(session: &AgentSession, presented: &SessionBinding) -> Option<ContractError> {
    let expected = session_binding(session);
    if presented.agent_session_epoch < expected.agent_session_epoch {
        return Some(detail(
            ContractErrorDetail::StaleSession {
                node_id: expected.node_id,
                presented_agent_session_epoch: presented.agent_session_epoch,
                current_agent_session_epoch: expected.agent_session_epoch,
            },
            "AgentSession is stale",
        ));
    }
    (presented != &expected).then(|| {
        detail(
            ContractErrorDetail::WrongSession {
                expected,
                presented: presented.clone(),
            },
            "request is not bound to the current AgentSession",
        )
    })
}

fn checked_next(value: Sequence, message: &'static str) -> AuthorityTxResult<Sequence> {
    value
        .get()
        .checked_add(1)
        .and_then(Sequence::new)
        .ok_or_else(|| corrupt(message))
}

fn checked_add_time(
    value: UnixMillis,
    increment: u64,
    context: &'static str,
) -> AuthorityTxResult<UnixMillis> {
    value
        .get()
        .checked_add(increment)
        .and_then(UnixMillis::new)
        .ok_or_else(|| corrupt(context))
}

fn detail(error: ContractErrorDetail, message: impl Into<String>) -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(error),
        message: message.into(),
    }
}

fn rejected<T>(error: ContractError) -> RuntimeSpineOutcome<T> {
    RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(error))
}

fn wrong_desired_sequence(
    session: &AgentSession,
    expected: Sequence,
    presented: Sequence,
) -> ContractError {
    detail(
        ContractErrorDetail::WrongDesiredReadSequence {
            node_id: session.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            expected_request_sequence: expected,
            presented_request_sequence: presented,
        },
        "Desired read sequence is not the next sequence",
    )
}

fn session_expired(session: &AgentSession, now: UnixMillis) -> ContractError {
    detail(
        ContractErrorDetail::SessionExpired {
            node_id: session.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            lease_deadline_unix_ms: session.lease_deadline_unix_ms,
            server_time_unix_ms: now,
        },
        "AgentSession lease has expired",
    )
}

fn assigned_limit(node_id: &Id, limit: AssignedSetLimit) -> ContractError {
    let (maximum, observed) = match limit {
        AssignedSetLimit::DesiredSpecs => (1024, 1025),
        AssignedSetLimit::WireBytes => (16_777_216, 16_777_217),
    };
    detail(
        ContractErrorDetail::AssignedSetLimitExceeded {
            node_id: node_id.clone(),
            limit,
            maximum: WireU64::new(maximum).expect("fixed maximum is a WireU64"),
            observed_at_least: WireU64::new(observed).expect("fixed lower bound is a WireU64"),
        },
        "assigned Desired set exceeds the closed limit",
    )
}

fn load_desired_read_state_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<DesiredReadState>> {
    transaction
        .query_opt(
            "SELECT response::text AS response_json, node_id, node_boot_id,
                    agent_instance_id, agent_session_epoch, last_request_sequence,
                    read_position_high_water, issued_at_unix_ms,
                    expires_at_unix_ms, consumed_observation_id,
                    consumed_heartbeat_sequence
               FROM runtime_desired_read_states WHERE node_id=$1 FOR UPDATE",
            &[&node_id.as_str()],
        )?
        .map(|row| decode_desired_read_state(&row))
        .transpose()
}

fn decode_desired_read_state(row: &Row) -> AuthorityTxResult<DesiredReadState> {
    let json: String = row.try_get("response_json")?;
    let response = decode_desired_read_snapshot(json.as_bytes()).map_err(corrupt)?;
    let node_id: String = row.try_get("node_id")?;
    let node_boot_id: String = row.try_get("node_boot_id")?;
    let agent_instance_id: String = row.try_get("agent_instance_id")?;
    let agent_session_epoch: Epoch = from_pg(row.try_get("agent_session_epoch")?)?;
    let last_request_sequence: Sequence = from_pg(row.try_get("last_request_sequence")?)?;
    let read_position: Sequence = from_pg(row.try_get("read_position_high_water")?)?;
    let issued_at: UnixMillis = from_pg(row.try_get("issued_at_unix_ms")?)?;
    let expires_at: UnixMillis = from_pg(row.try_get("expires_at_unix_ms")?)?;
    let consumed_observation_id: Option<String> = row.try_get("consumed_observation_id")?;
    let consumed_sequence: Option<i64> = row.try_get("consumed_heartbeat_sequence")?;
    if response.session.node_id.as_str() != node_id
        || response.session.node_boot_id.as_str() != node_boot_id
        || response.session.agent_instance_id.as_str() != agent_instance_id
        || response.session.agent_session_epoch != agent_session_epoch
        || response.request_sequence != last_request_sequence
        || response.read_position != read_position
        || response.issued_at_unix_ms != issued_at
        || response.expires_at_unix_ms != expires_at
    {
        return Err(corrupt("Desired read state JSON/projection mismatch"));
    }
    let consumed_by = match (consumed_observation_id, consumed_sequence) {
        (None, None) => None,
        (Some(id), Some(sequence)) => Some((
            RandomId128::new(id).ok_or_else(|| corrupt("invalid consumed observation ID"))?,
            from_pg(sequence)?,
        )),
        _ => return Err(corrupt("partial Desired cursor consumption projection")),
    };
    Ok(DesiredReadState {
        response,
        consumed_by,
    })
}

fn upsert_desired_read_state(
    transaction: &mut Transaction<'_>,
    state: &DesiredReadState,
) -> AuthorityTxResult<()> {
    let response =
        String::from_utf8(encode_desired_read_snapshot(&state.response).map_err(corrupt)?)
            .map_err(corrupt)?;
    let request_sequence = state.response.request_sequence.to_pg().map_err(corrupt)?;
    let read_position = state.response.read_position.to_pg().map_err(corrupt)?;
    let issued_at = state.response.issued_at_unix_ms.to_pg().map_err(corrupt)?;
    let expires_at = state.response.expires_at_unix_ms.to_pg().map_err(corrupt)?;
    let (consumed_id, consumed_sequence) = match &state.consumed_by {
        Some((id, sequence)) => (Some(id.as_str()), Some(sequence.to_pg().map_err(corrupt)?)),
        None => (None, None),
    };
    let epoch = state
        .response
        .session
        .agent_session_epoch
        .to_pg()
        .map_err(corrupt)?;
    transaction.execute(
        "INSERT INTO runtime_desired_read_states (
            node_id, response, node_boot_id, agent_instance_id,
            agent_session_epoch, last_request_sequence,
            read_position_high_water, issued_at_unix_ms, expires_at_unix_ms,
            consumed_observation_id, consumed_heartbeat_sequence
         ) VALUES ($1,$2::TEXT::jsonb,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (node_id) DO UPDATE SET
            response=EXCLUDED.response, node_boot_id=EXCLUDED.node_boot_id,
            agent_instance_id=EXCLUDED.agent_instance_id,
            agent_session_epoch=EXCLUDED.agent_session_epoch,
            last_request_sequence=EXCLUDED.last_request_sequence,
            read_position_high_water=EXCLUDED.read_position_high_water,
            issued_at_unix_ms=EXCLUDED.issued_at_unix_ms,
            expires_at_unix_ms=EXCLUDED.expires_at_unix_ms,
            consumed_observation_id=EXCLUDED.consumed_observation_id,
            consumed_heartbeat_sequence=EXCLUDED.consumed_heartbeat_sequence",
        &[
            &state.response.session.node_id.as_str(),
            &response,
            &state.response.session.node_boot_id.as_str(),
            &state.response.session.agent_instance_id.as_str(),
            &epoch,
            &request_sequence,
            &read_position,
            &issued_at,
            &expires_at,
            &consumed_id,
            &consumed_sequence,
        ],
    )?;
    Ok(())
}

fn from_pg<T: PgBigInt>(value: i64) -> AuthorityTxResult<T> {
    T::from_pg(value).map_err(corrupt)
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    cats_storage::authority::AuthorityError::BackendUnknown.into()
}

// Observation acceptance is implemented below the row codecs so both the
// first-commit path and the exact replay path use the same decoded state.
fn accept_observation_in(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    observation: &NodeObservation,
) -> AuthorityTxResult<RuntimeSpineOutcome<ObservationAcceptance>> {
    accept_observation_core(transaction, authenticated, observation)
}

enum ValidatedInventory {
    Full {
        desired_state: DesiredReadState,
        current_desired: Vec<DesiredRuntimeSpec>,
    },
    Partial {
        inventory: Box<AdmissionInventoryState>,
    },
}

fn accept_observation_core(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    observation: &NodeObservation,
) -> AuthorityTxResult<RuntimeSpineOutcome<ObservationAcceptance>> {
    let Some(identity) = authenticate_identity(transaction, authenticated)? else {
        return Ok(RuntimeSpineOutcome::Rejected(
            RuntimeSpineRejection::IdentityNotEligible,
        ));
    };
    let Some(session) = load_current_session_for_update(transaction, &identity.node_id)? else {
        return Ok(rejected(detail(
            ContractErrorDetail::MissingAgentSession {
                node_id: identity.node_id,
            },
            "authenticated Node has no current AgentSession",
        )));
    };
    let presented_binding = observation_binding(observation);
    if let Some(error) = session_error(&session, &presented_binding) {
        return Ok(rejected(error));
    }

    let receive_state = load_observation_receive_state_for_update(transaction, &session.node_id)?;
    let same_receive_session = receive_state
        .as_ref()
        .is_some_and(|state| state.acceptance.session == presented_binding);
    if same_receive_session {
        let retained = receive_state
            .as_ref()
            .expect("same receive-state session exists");
        if observation.heartbeat_sequence < retained.observation.heartbeat_sequence {
            return Ok(rejected(detail(
                ContractErrorDetail::StaleObservationSequence {
                    node_id: session.node_id,
                    agent_session_epoch: session.agent_session_epoch,
                    presented_heartbeat_sequence: observation.heartbeat_sequence,
                    last_accepted_heartbeat_sequence: retained.observation.heartbeat_sequence,
                },
                "observation sequence is stale",
            )));
        }
        if observation.heartbeat_sequence == retained.observation.heartbeat_sequence {
            if observation == &retained.observation {
                return Ok(RuntimeSpineOutcome::Accepted(retained.acceptance.clone()));
            }
            return Ok(rejected(detail(
                ContractErrorDetail::ObservationSequenceConflict {
                    node_id: session.node_id,
                    agent_session_epoch: session.agent_session_epoch,
                    heartbeat_sequence: observation.heartbeat_sequence,
                    accepted_observation_id: retained.observation.observation_id.clone(),
                    presented_observation_id: observation.observation_id.clone(),
                },
                "same observation sequence carried a different payload",
            )));
        }
    }

    let now = database_now(transaction)?;
    if now >= session.lease_deadline_unix_ms {
        return Ok(rejected(session_expired(&session, now)));
    }
    if receive_state
        .as_ref()
        .is_some_and(|state| now < state.acceptance.accepted_at_unix_ms)
    {
        return Err(corrupt(
            "database time moved behind last accepted observation",
        ));
    }

    let inventory = match validate_inventory(transaction, &session, observation, now)? {
        Ok(inventory) => inventory,
        Err(error) => return Ok(rejected(error)),
    };
    if let Some(error) = validate_and_settle_operations(transaction, observation, &inventory, now)?
    {
        return Ok(rejected(error));
    }

    let candidate_deadline =
        checked_add_time(now, AGENT_SESSION_LEASE_MS, "session lease renewal")?;
    let renewed_deadline = std::cmp::max(session.lease_deadline_unix_ms, candidate_deadline);
    let inventory_acceptance = match &inventory {
        ValidatedInventory::Full { .. } => ObservationInventoryAcceptance::Full {
            attestation: AdmissionInventoryAttestation {
                version: ContractVersion::V1,
                node_id: observation.node_id.clone(),
                agent_session_epoch: observation.agent_session_epoch,
                inventory_epoch: observation.inventory_epoch,
                inventory_digest: observation
                    .inventory_digest
                    .clone()
                    .ok_or_else(|| corrupt("full observation lost inventory digest"))?,
                inventory_read_position: observation
                    .inventory_read_position
                    .ok_or_else(|| corrupt("full observation lost read position"))?,
                accepted_at_unix_ms: now,
            },
        },
        ValidatedInventory::Partial { .. } => ObservationInventoryAcceptance::Partial {
            inventory_epoch: observation.inventory_epoch,
        },
    };
    let acceptance = ObservationAcceptance {
        version: ContractVersion::V1,
        session: presented_binding,
        observation_id: observation.observation_id.clone(),
        heartbeat_sequence: observation.heartbeat_sequence,
        accepted_at_unix_ms: now,
        lease_deadline_unix_ms: renewed_deadline,
        inventory: inventory_acceptance,
    };
    encode_observation_acceptance(&acceptance).map_err(corrupt)?;

    match inventory {
        ValidatedInventory::Full {
            mut desired_state,
            current_desired: _,
        } => {
            let attestation = match &acceptance.inventory {
                ObservationInventoryAcceptance::Full { attestation } => attestation.clone(),
                ObservationInventoryAcceptance::Partial { .. } => {
                    return Err(corrupt("full validation produced partial acceptance"));
                }
            };
            desired_state.consumed_by = Some((
                observation.observation_id.clone(),
                observation.heartbeat_sequence,
            ));
            upsert_desired_read_state(transaction, &desired_state)?;
            upsert_admission_inventory_state(
                transaction,
                &AdmissionInventoryState {
                    attestation,
                    full_observation: observation.clone(),
                    assigned_snapshot: desired_state.response.clone(),
                },
            )?;
            replace_full_cat_observations(transaction, observation, now)?;
        }
        ValidatedInventory::Partial { inventory: _ } => {
            upsert_partial_cat_observations(transaction, observation, now)?;
        }
    }
    upsert_observation_receive_state(
        transaction,
        &ObservationReceiveState {
            observation: observation.clone(),
            acceptance: acceptance.clone(),
        },
    )?;
    renew_current_session_deadline(transaction, &session, renewed_deadline)?;
    Ok(RuntimeSpineOutcome::Accepted(acceptance))
}

fn validate_inventory(
    transaction: &mut Transaction<'_>,
    session: &AgentSession,
    observation: &NodeObservation,
    now: UnixMillis,
) -> ContextValidation<ValidatedInventory> {
    if observation.complete_inventory {
        let desired_state = load_desired_read_state_for_update(transaction, &session.node_id)?;
        let inventory_state =
            load_admission_inventory_state_for_update(transaction, &session.node_id)?;
        let Some(desired_state) =
            desired_state.filter(|state| state.response.session == session_binding(session))
        else {
            return Ok(Err(detail(
                ContractErrorDetail::MissingInventoryReadPosition {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                },
                "full inventory has no current Desired cursor",
            )));
        };
        let presented_position = observation
            .inventory_read_position
            .ok_or_else(|| corrupt("full observation has no read position"))?;
        let current_position = desired_state.response.read_position;
        if presented_position < current_position {
            return Ok(Err(detail(
                ContractErrorDetail::StaleInventoryReadPosition {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    presented_read_position: presented_position,
                    current_read_position: current_position,
                },
                "inventory read position is stale",
            )));
        }
        if presented_position > current_position {
            return Ok(Err(detail(
                ContractErrorDetail::WrongInventoryReadPosition {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    current_read_position: current_position,
                    presented_read_position: presented_position,
                },
                "inventory read position is not current",
            )));
        }
        if let Some((observation_id, sequence)) = &desired_state.consumed_by {
            return Ok(Err(detail(
                ContractErrorDetail::InventoryReadPositionConsumed {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    read_position: current_position,
                    accepted_observation_id: observation_id.clone(),
                    accepted_heartbeat_sequence: *sequence,
                },
                "inventory read position is already consumed",
            )));
        }
        if desired_state.response.issued_at_unix_ms >= desired_state.response.expires_at_unix_ms
            || now < desired_state.response.issued_at_unix_ms
        {
            return Err(corrupt("Desired cursor time causality is corrupt"));
        }
        if now >= desired_state.response.expires_at_unix_ms {
            return Ok(Err(detail(
                ContractErrorDetail::InventoryReadPositionExpired {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    read_position: current_position,
                    expires_at_unix_ms: desired_state.response.expires_at_unix_ms,
                    server_time_unix_ms: now,
                },
                "inventory read position expired",
            )));
        }
        lock_product_dependencies(
            transaction,
            &desired_state.response.desired_specs,
            observation,
        )?;
        let current_desired = load_assigned_desired_for_update(transaction, &session.node_id)?;
        if current_desired != desired_state.response.desired_specs {
            return Ok(Err(detail(
                ContractErrorDetail::AssignedSetChanged {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    read_position: current_position,
                },
                "assigned Desired set changed after cursor issuance",
            )));
        }
        if let Err(error) =
            validate_full_inventory_epoch(session, observation, inventory_state.as_ref())?
        {
            return Ok(Err(error));
        }
        let runtimes: BTreeMap<&Id, &ObservedRuntimeStatus> = observation
            .runtimes
            .iter()
            .map(|runtime| (&runtime.cat_id, runtime))
            .collect();
        for desired in &current_desired {
            let Some(runtime) = runtimes.get(&desired.cat_id) else {
                return Ok(Err(detail(
                    ContractErrorDetail::IncompleteAssignedInventory {
                        node_id: session.node_id.clone(),
                        agent_session_epoch: session.agent_session_epoch,
                        read_position: current_position,
                        missing_cat_id: desired.cat_id.clone(),
                    },
                    "full inventory omitted an assigned Cat",
                )));
            };
            let expected = applied_projection(desired);
            if runtime.applied_desired.as_ref() != Some(&expected) {
                return Ok(Err(detail(
                    ContractErrorDetail::AssignedRuntimeBindingMismatch {
                        node_id: session.node_id.clone(),
                        agent_session_epoch: session.agent_session_epoch,
                        read_position: current_position,
                        cat_id: desired.cat_id.clone(),
                        expected,
                        presented: runtime.applied_desired.clone(),
                    },
                    "assigned runtime binding does not match its Desired snapshot",
                )));
            }
        }
        Ok(Ok(ValidatedInventory::Full {
            desired_state,
            current_desired,
        }))
    } else {
        let inventory_state =
            load_admission_inventory_state_for_update(transaction, &session.node_id)?;
        let Some(inventory) = inventory_state.filter(|state| {
            observation_binding(&state.full_observation) == session_binding(session)
        }) else {
            return Ok(Err(detail(
                ContractErrorDetail::MissingInventoryAttestation {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                },
                "partial observation has no current full attestation",
            )));
        };
        if let Err(error) = compare_partial_inventory_epoch(
            session,
            observation,
            inventory.attestation.inventory_epoch,
        )? {
            return Ok(Err(error));
        }
        let full_members: BTreeSet<&Id> = inventory
            .full_observation
            .runtimes
            .iter()
            .map(|runtime| &runtime.cat_id)
            .collect();
        if let Some(runtime) = observation
            .runtimes
            .iter()
            .find(|runtime| !full_members.contains(&runtime.cat_id))
        {
            return Ok(Err(detail(
                ContractErrorDetail::PartialCatNotInFullInventory {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    inventory_epoch: observation.inventory_epoch,
                    cat_id: runtime.cat_id.clone(),
                },
                "partial observation cannot expand full inventory membership",
            )));
        }
        lock_product_dependencies(
            transaction,
            &inventory.assigned_snapshot.desired_specs,
            observation,
        )?;
        Ok(Ok(ValidatedInventory::Partial {
            inventory: Box::new(inventory),
        }))
    }
}

fn lock_product_dependencies(
    transaction: &mut Transaction<'_>,
    desired_specs: &[DesiredRuntimeSpec],
    observation: &NodeObservation,
) -> AuthorityTxResult<()> {
    let mut volume_ids: BTreeSet<String> = desired_specs
        .iter()
        .flat_map(|desired| {
            desired
                .volumes
                .iter()
                .map(|volume| volume.volume_id.to_string())
        })
        .collect();
    let mut disk_ids: BTreeSet<String> = desired_specs
        .iter()
        .flat_map(|desired| {
            desired
                .volumes
                .iter()
                .map(|volume| volume.disk_id.to_string())
        })
        .collect();

    // A partial observation may report a Cat that was an orphan in the last
    // full inventory but has since gained a current Pending Operation. Read
    // only the dependency identities here; the full Desired row is decoded
    // and judged only after the global Volume/Disk lock set is held.
    let candidate_cat_ids: Vec<&str> = observation
        .runtimes
        .iter()
        .filter(|runtime| runtime.applied_desired.is_some())
        .map(|runtime| runtime.cat_id.as_str())
        .collect();
    if !candidate_cat_ids.is_empty() {
        for row in transaction.query(
            "SELECT item->>'volume_id' AS volume_id, item->>'disk_id' AS disk_id
               FROM desired_runtime_specs d
               CROSS JOIN LATERAL jsonb_array_elements(
                 CASE WHEN jsonb_typeof(d.record->'volumes')='array'
                      THEN d.record->'volumes' ELSE '[]'::jsonb END
               ) item
              WHERE d.cat_id = ANY($1)",
            &[&candidate_cat_ids],
        )? {
            if let Some(volume_id) = row.try_get::<_, Option<String>>("volume_id")? {
                volume_ids.insert(volume_id);
            }
            if let Some(disk_id) = row.try_get::<_, Option<String>>("disk_id")? {
                disk_ids.insert(disk_id);
            }
        }
    }

    for volume_id in volume_ids {
        transaction.query_opt(
            "SELECT volume_id FROM volume_records WHERE volume_id=$1 FOR UPDATE",
            &[&volume_id],
        )?;
    }
    for disk_id in disk_ids {
        transaction.query_opt(
            "SELECT disk_id FROM disk_records WHERE disk_id=$1 FOR UPDATE",
            &[&disk_id],
        )?;
    }
    Ok(())
}

fn validate_full_inventory_epoch(
    session: &AgentSession,
    observation: &NodeObservation,
    current: Option<&AdmissionInventoryState>,
) -> ContextValidation<()> {
    let current = current
        .filter(|state| observation_binding(&state.full_observation) == session_binding(session));
    let Some(current) = current else {
        let expected = Epoch::new(1).expect("one is an Epoch");
        if observation.inventory_epoch != expected {
            return Ok(Err(detail(
                ContractErrorDetail::WrongInventoryEpoch {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    expected_inventory_epoch: expected,
                    presented_inventory_epoch: observation.inventory_epoch,
                },
                "first full inventory epoch must be one",
            )));
        }
        return Ok(Ok(()));
    };
    let current_epoch = current.attestation.inventory_epoch;
    let expected = current_epoch
        .get()
        .checked_add(1)
        .and_then(Epoch::new)
        .ok_or_else(|| corrupt("inventory epoch exhausted"))?;
    if observation.inventory_epoch <= current_epoch {
        return Ok(Err(detail(
            ContractErrorDetail::StaleInventoryEpoch {
                node_id: session.node_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
                presented_inventory_epoch: observation.inventory_epoch,
                current_inventory_epoch: current_epoch,
            },
            "full inventory epoch is stale",
        )));
    }
    if observation.inventory_epoch != expected {
        return Ok(Err(detail(
            ContractErrorDetail::WrongInventoryEpoch {
                node_id: session.node_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
                expected_inventory_epoch: expected,
                presented_inventory_epoch: observation.inventory_epoch,
            },
            "full inventory epoch skipped the next epoch",
        )));
    }
    Ok(Ok(()))
}

fn compare_partial_inventory_epoch(
    session: &AgentSession,
    observation: &NodeObservation,
    current: Epoch,
) -> ContextValidation<()> {
    if observation.inventory_epoch < current {
        return Ok(Err(detail(
            ContractErrorDetail::StaleInventoryEpoch {
                node_id: session.node_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
                presented_inventory_epoch: observation.inventory_epoch,
                current_inventory_epoch: current,
            },
            "partial inventory epoch is stale",
        )));
    }
    if observation.inventory_epoch > current {
        let expected = current;
        return Ok(Err(detail(
            ContractErrorDetail::WrongInventoryEpoch {
                node_id: session.node_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
                expected_inventory_epoch: expected,
                presented_inventory_epoch: observation.inventory_epoch,
            },
            "partial inventory epoch is not current",
        )));
    }
    Ok(Ok(()))
}

fn applied_projection(desired: &DesiredRuntimeSpec) -> AppliedDesiredEvidence {
    AppliedDesiredEvidence {
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        target: desired.target,
    }
}

struct SettlementCandidate<'a> {
    runtime_index: usize,
    runtime: &'a ObservedRuntimeStatus,
    desired: DesiredRuntimeSpec,
    operation: Operation,
}

/// Validate the three frozen settlement stages over the complete candidate
/// set before considering any terminal condition. Writes happen only after
/// every Cat has passed revision, digest, placement and condition binding.
fn validate_and_settle_operations(
    transaction: &mut Transaction<'_>,
    observation: &NodeObservation,
    inventory: &ValidatedInventory,
    now: UnixMillis,
) -> AuthorityTxResult<Option<ContractError>> {
    // The cheap existence probe is not authority: it only bounds the set of
    // rows whose Desired rows must be locked first. The authoritative Pending
    // row is re-read FOR UPDATE below.
    let mut candidate_indexes = Vec::new();
    for (index, runtime) in observation.runtimes.iter().enumerate() {
        if runtime.applied_desired.is_none() {
            continue;
        }
        if transaction
            .query_opt(
                "SELECT operation_id FROM runtime_operations
                  WHERE cat_id=$1 AND phase='pending'",
                &[&runtime.cat_id.as_str()],
            )?
            .is_some()
        {
            candidate_indexes.push(index);
        }
    }

    let mut desired_rows = BTreeMap::new();
    for index in &candidate_indexes {
        let cat_id = &observation.runtimes[*index].cat_id;
        let desired = load_desired_for_update(transaction, cat_id)?
            .ok_or_else(|| corrupt("Pending Operation has no current Desired row"))?;
        desired_rows.insert(cat_id.clone(), desired);
    }

    let mut candidates = Vec::new();
    for index in candidate_indexes {
        let runtime = &observation.runtimes[index];
        let Some(operation) =
            load_pending_operation_by_cat_for_update(transaction, &runtime.cat_id)?
        else {
            // It may have become terminal before its Desired lock was acquired.
            // Only rows still current+Pending participate in this transaction.
            continue;
        };
        let desired = desired_rows
            .remove(&runtime.cat_id)
            .ok_or_else(|| corrupt("settlement Desired lock set is incomplete"))?;
        candidates.push(SettlementCandidate {
            runtime_index: index,
            runtime,
            desired,
            operation,
        });
    }

    // Stage 4: each source is checked in the frozen source order, and the
    // outer scan restarts at the smallest Cat for every stage.
    for candidate in &candidates {
        let expected = candidate.desired.desired_revision;
        if candidate.operation.desired_revision != expected {
            return Ok(Some(revision_error(
                &candidate.runtime.cat_id,
                expected,
                candidate.operation.desired_revision,
            )));
        }
        let applied = candidate
            .runtime
            .applied_desired
            .as_ref()
            .ok_or_else(|| corrupt("settlement candidate lost applied Desired"))?;
        if applied.desired_revision != expected {
            return Ok(Some(revision_error(
                &candidate.runtime.cat_id,
                expected,
                applied.desired_revision,
            )));
        }
    }

    // The one DB timestamp governs the whole settlement attempt even when a
    // candidate remains Pending. Accepting a newer observation while an
    // Operation carries a future server timestamp would otherwise conceal a
    // database-clock rollback and allow a later terminal time to move back.
    for candidate in &candidates {
        if now < candidate.operation.created_at_unix_ms
            || now < candidate.operation.updated_at_unix_ms
        {
            return Err(corrupt("database time moved behind an Operation"));
        }
    }

    // Stage 5: stored Operation first, then presented applied evidence.
    for candidate in &candidates {
        let expected = &candidate.desired.spec_digest;
        if &candidate.operation.desired_spec_digest != expected {
            return Ok(Some(digest_error(
                &candidate.desired,
                candidate.operation.desired_spec_digest.clone(),
            )));
        }
        let applied = candidate
            .runtime
            .applied_desired
            .as_ref()
            .ok_or_else(|| corrupt("settlement candidate lost applied Desired"))?;
        if &applied.spec_digest != expected {
            return Ok(Some(digest_error(
                &candidate.desired,
                applied.spec_digest.clone(),
            )));
        }
    }

    // Stage 6: Operation, applied evidence, then the top-level Node.
    for candidate in &candidates {
        let expected = &candidate.desired.placement;
        if &candidate.operation.placement != expected {
            return Ok(Some(placement_error(
                &candidate.desired,
                candidate.operation.placement.clone(),
            )));
        }
        let applied = candidate
            .runtime
            .applied_desired
            .as_ref()
            .ok_or_else(|| corrupt("settlement candidate lost applied Desired"))?;
        if &applied.placement != expected {
            return Ok(Some(placement_error(
                &candidate.desired,
                applied.placement.clone(),
            )));
        }
        if observation.node_id != expected.node_id {
            return Ok(Some(placement_error(
                &candidate.desired,
                AssignedPlacement {
                    kind: AssignedKind::Assigned,
                    node_id: observation.node_id.clone(),
                    placement_epoch: expected.placement_epoch,
                },
            )));
        }
    }

    // Stage 7 starts by validating every placement_rejected reason, including
    // later/unselected conditions. A malformed reason rejects the whole input.
    for candidate in &candidates {
        if candidate.operation.workspace_id != candidate.desired.workspace_id
            || candidate.operation.cat_id != candidate.desired.cat_id
            || candidate.operation.target != candidate.desired.target
        {
            return Err(corrupt(
                "current Operation identity/target does not match current Desired",
            ));
        }
        for (condition_index, condition) in candidate.runtime.conditions.iter().enumerate() {
            let Condition::PreconditionFailed {
                reason:
                    PreconditionFailureReason::PlacementRejected {
                        node_id,
                        placement_epoch,
                        ..
                    },
            } = condition
            else {
                continue;
            };
            if node_id != &candidate.operation.placement.node_id {
                return Ok(Some(invalid_condition_binding(
                    candidate.runtime_index,
                    condition_index,
                    "node_id",
                )));
            }
            if placement_epoch != &candidate.operation.placement.placement_epoch {
                return Ok(Some(invalid_condition_binding(
                    candidate.runtime_index,
                    condition_index,
                    "placement_epoch",
                )));
            }
        }
    }

    // Disk/Volume rows were locked while validating product dependencies and
    // Pending Operation rows were then locked in canonical Cat order. Finish
    // the frozen product lock order by coordinating every delete receipt in
    // lexical id order before terminal selection. This probe deliberately
    // does not decode or branch on a receipt: the postcondition re-reads the
    // authoritative row below, while this pass prevents two multi-Cat
    // observations from acquiring receipt locks in opposite Desired order.
    let delete_ids: BTreeSet<Id> = candidates
        .iter()
        .flat_map(|candidate| candidate.desired.volumes.iter())
        .filter_map(|intent| match &intent.disposition {
            cats_api::runtime_reconciliation::VolumeDisposition::DeleteDisposableRoot {
                delete_id,
            } => Some(delete_id.clone()),
            cats_api::runtime_reconciliation::VolumeDisposition::Retain
            | cats_api::runtime_reconciliation::VolumeDisposition::DetachRetained => None,
        })
        .collect();
    for delete_id in delete_ids {
        transaction.query_opt(
            "SELECT delete_id FROM delete_completion_receipts
              WHERE delete_id=$1 FOR UPDATE",
            &[&delete_id.as_str()],
        )?;
    }

    let mut replacements = Vec::new();
    for candidate in candidates {
        let terminal_failure =
            candidate
                .runtime
                .conditions
                .iter()
                .find_map(|condition| match condition {
                    Condition::PreconditionFailed { reason } => {
                        Some(OperationFailure::PreconditionFailed {
                            reason: reason.clone(),
                        })
                    }
                    Condition::Quarantined { reason } => Some(OperationFailure::Quarantined {
                        reason: Box::new(reason.clone()),
                    }),
                    _ => None,
                });
        let terminal = if let Some(error) = terminal_failure {
            Some((
                OperationPhase::Failed,
                OperationTerminal::Failed {
                    error: Box::new(error),
                    completed_at_unix_ms: now,
                },
            ))
        } else if stable_postcondition_satisfied(
            transaction,
            observation,
            inventory,
            candidate.runtime,
            &candidate.desired,
        )? {
            Some((
                OperationPhase::Succeeded,
                OperationTerminal::Succeeded {
                    result: OperationSuccess {
                        observation_id: observation.observation_id.clone(),
                        node_id: observation.node_id.clone(),
                        agent_session_epoch: observation.agent_session_epoch,
                        heartbeat_sequence: observation.heartbeat_sequence,
                        observed_target: candidate.desired.target,
                        runtime_incarnation: candidate.runtime.runtime_incarnation.clone(),
                    },
                    completed_at_unix_ms: now,
                },
            ))
        } else {
            None
        };
        if let Some((phase, terminal)) = terminal {
            let mut replacement = candidate.operation;
            replacement.phase = phase;
            replacement.terminal = Some(terminal);
            replacement.updated_at_unix_ms = now;
            replacements.push(replacement);
        }
    }

    // No Operation row is changed until all candidates and all time guards
    // have passed, so any preceding rejection is genuinely zero-side-effect.
    for replacement in &replacements {
        update_operation(transaction, replacement)?;
    }
    Ok(None)
}

fn revision_error(cat_id: &Id, expected: Revision, presented: Revision) -> ContractError {
    if presented < expected {
        detail(
            ContractErrorDetail::StaleRevision {
                cat_id: cat_id.clone(),
                presented_revision: presented,
                current_revision: expected,
            },
            "runtime Desired revision is stale",
        )
    } else {
        detail(
            ContractErrorDetail::WrongRevision {
                cat_id: cat_id.clone(),
                expected_revision: expected,
                presented_revision: presented,
            },
            "runtime Desired revision is not current",
        )
    }
}

fn digest_error(
    desired: &DesiredRuntimeSpec,
    presented: cats_api::runtime_reconciliation::Sha256Digest,
) -> ContractError {
    detail(
        ContractErrorDetail::RevisionDigestConflict {
            cat_id: desired.cat_id.clone(),
            desired_revision: desired.desired_revision,
            expected_digest: desired.spec_digest.clone(),
            presented_digest: presented,
        },
        "runtime Desired digest conflicts with the current revision",
    )
}

fn placement_error(desired: &DesiredRuntimeSpec, presented: AssignedPlacement) -> ContractError {
    detail(
        ContractErrorDetail::WrongPlacement {
            cat_id: desired.cat_id.clone(),
            desired_revision: desired.desired_revision,
            expected: desired.placement.clone(),
            presented,
        },
        "runtime placement is not current",
    )
}

fn invalid_condition_binding(
    runtime_index: usize,
    condition_index: usize,
    field: &str,
) -> ContractError {
    let pointer = JsonPointer::new(format!(
        "/runtimes/{runtime_index}/conditions/{condition_index}/reason/{field}"
    ))
    .expect("fixed observation condition path is a JSON pointer");
    detail(
        ContractErrorDetail::MalformedPayload {
            contract: ContractName::NodeObservation,
            json_pointer: pointer,
            problem: MalformedProblem::InvalidValue,
        },
        "placement_rejected reason is not bound to the current placement",
    )
}

fn stable_postcondition_satisfied(
    transaction: &mut Transaction<'_>,
    observation: &NodeObservation,
    inventory: &ValidatedInventory,
    runtime: &ObservedRuntimeStatus,
    desired: &DesiredRuntimeSpec,
) -> AuthorityTxResult<bool> {
    if runtime
        .applied_desired
        .as_ref()
        .is_none_or(|applied| applied.target != desired.target)
    {
        return Ok(false);
    }
    let stable_target = runtime.stable_state.map(|state| match state {
        StableState::Running => RuntimeTarget::Running,
        StableState::Suspended => RuntimeTarget::Suspended,
        StableState::Warm => RuntimeTarget::Warm,
        StableState::Cold => RuntimeTarget::Cold,
        StableState::Deleted => RuntimeTarget::Deleted,
    });
    let ready = runtime.conditions.iter().any(|condition| {
        matches!(
            condition,
            Condition::Ready {
                reason: ReadyReason::PostconditionSatisfied { target }
            } if *target == desired.target
        )
    });
    let step_matches = matches!(
        runtime.step,
        ReconcileStep::Stable { state }
            if stable_target == Some(match state {
                StableState::Running => RuntimeTarget::Running,
                StableState::Suspended => RuntimeTarget::Suspended,
                StableState::Warm => RuntimeTarget::Warm,
                StableState::Cold => RuntimeTarget::Cold,
                StableState::Deleted => RuntimeTarget::Deleted,
            })
    );
    let full_residue_empty = match inventory {
        ValidatedInventory::Full { .. } => observation.residue.is_empty(),
        ValidatedInventory::Partial { inventory } => inventory.full_observation.residue.is_empty(),
    };
    let logical = ready
        && stable_target == Some(desired.target)
        && step_matches
        && desired.placement.node_id == observation.node_id
        && full_residue_empty
        && (desired.target == RuntimeTarget::Running || runtime.platform_guards == 0);
    if !logical {
        return Ok(false);
    }
    database_postcondition_satisfied(transaction, runtime, desired)
}

fn database_postcondition_satisfied(
    transaction: &mut Transaction<'_>,
    runtime: &ObservedRuntimeStatus,
    desired: &DesiredRuntimeSpec,
) -> AuthorityTxResult<bool> {
    if !checkpoint_matches(runtime, desired) {
        return Ok(false);
    }
    let expected_admission = if desired.target == RuntimeTarget::Running {
        LifecycleAdmission::Open
    } else {
        LifecycleAdmission::Closed
    };
    if runtime.lifecycle_admission != expected_admission {
        return Ok(false);
    }
    // Warm success requires a locked Control snapshot record. That authority
    // is not present in the current schema slice, so fail closed instead of
    // treating the Node's snapshot-shaped payload as a proof.
    if desired.target == RuntimeTarget::Warm {
        return Ok(false);
    }

    if desired.target == RuntimeTarget::Deleted {
        return deleted_postcondition_satisfied(transaction, runtime, desired);
    }

    if !routes_match(runtime, desired) || !runtime_shape_matches(runtime, desired) {
        return Ok(false);
    }
    if runtime.volumes.len() != desired.volumes.len() {
        return Ok(false);
    }
    for intent in &desired.volumes {
        let Some(disk) = load_disk_by_id_for_update(transaction, &intent.disk_id)? else {
            return Ok(false);
        };
        let Some(volume) = load_volume_for_update(transaction, &intent.volume_id)? else {
            return Ok(false);
        };
        if disk.workspace_id != desired.workspace_id
            || disk.volume_id != intent.volume_id
            || disk.size_bytes != intent.size_bytes
            || volume.volume_id != intent.volume_id
            || volume.size_bytes != intent.size_bytes
            || !durability_matches(intent.durability, disk.durability)
            || !durability_matches(intent.durability, volume.durability)
            || !disk_kind_matches(intent.disk_kind, &disk.role, &desired.cat_id)
            || !matches!(disk.admin_state, DiskAdminState::Active)
            || !matches!(volume.admin_state, VolumeAdminState::Active)
        {
            return Ok(false);
        }
        let Some(observed) = runtime
            .volumes
            .iter()
            .find(|observed| observed.volume_id == intent.volume_id)
        else {
            return Ok(false);
        };
        if observed.volume_intent_id.as_ref() != Some(&intent.volume_intent_id)
            || observed.disk_id.as_ref() != Some(&intent.disk_id)
            || observed.size_bytes != Some(intent.size_bytes)
            || observed.durability != Some(intent.durability)
            || !observed_disk_kind_matches(intent.disk_kind, observed.disk_kind)
            || observed.authority != authority_projection(&volume)
        {
            return Ok(false);
        }
        match desired.target {
            RuntimeTarget::Running | RuntimeTarget::Suspended => {
                if volume.lease_owner.as_ref() != Some(&intent.attachment_id)
                    || !active_volume_evidence_matches(runtime, observed, intent, &volume, desired)
                {
                    return Ok(false);
                }
            }
            RuntimeTarget::Cold => {
                if volume.lease_owner.is_some()
                    || !cold_volume_evidence_matches(observed, intent, &volume, desired)
                {
                    return Ok(false);
                }
            }
            RuntimeTarget::Warm | RuntimeTarget::Deleted => unreachable!("handled above"),
        }
        if intent.disk_kind == cats_api::runtime_reconciliation::DiskKind::Root
            && volume.head.generation.get() == 0
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn checkpoint_matches(runtime: &ObservedRuntimeStatus, desired: &DesiredRuntimeSpec) -> bool {
    let cats_api::runtime_reconciliation::CheckpointEvidence::Valid {
        cat_id,
        node_id,
        desired_revision,
        spec_digest,
        placement_epoch,
        runtime_incarnation,
        stable_state,
        step,
        ..
    } = &runtime.checkpoint
    else {
        return false;
    };
    cat_id == &desired.cat_id
        && node_id == &desired.placement.node_id
        && desired_revision == &desired.desired_revision
        && spec_digest == &desired.spec_digest
        && placement_epoch == &desired.placement.placement_epoch
        && runtime_incarnation == &runtime.runtime_incarnation
        && stable_state == &runtime.stable_state
        && step.as_ref() == &runtime.step
}

fn runtime_shape_matches(runtime: &ObservedRuntimeStatus, desired: &DesiredRuntimeSpec) -> bool {
    match desired.target {
        RuntimeTarget::Running | RuntimeTarget::Suspended => {
            let Some(incarnation) = runtime.runtime_incarnation.as_ref() else {
                return false;
            };
            let vmm: Vec<_> = runtime
                .processes
                .iter()
                .filter(|process| matches!(process.role, ProcessRole::Vmm { .. }))
                .collect();
            if vmm.len() != 1 {
                return false;
            }
            let vmm = vmm[0];
            let expected_state = if desired.target == RuntimeTarget::Running {
                ProcessState::Running
            } else {
                ProcessState::Paused
            };
            let process_matches = matches!(
                &vmm.role,
                ProcessRole::Vmm { runtime_incarnation } if runtime_incarnation == incarnation
            ) && vmm.state == expected_state
                && matches!(
                    vmm.control_handshake,
                    cats_api::runtime_reconciliation::ControlHandshakeEvidence::Verified
                )
                && matches!(vmm.ownership_token, OwnershipTokenEvidence::Valid { .. })
                && vmm.observed_vm_shape.as_ref().is_some_and(|shape| {
                    shape.vcpus == desired.runtime.vcpus
                        && shape.memory_bytes == desired.runtime.memory_bytes
                        && shape.boot_image_digest == desired.runtime.boot_image_digest
                        && shape.guest_config_digest == desired.runtime.guest_config_digest
                });
            let guest_matches = matches!(
                &runtime.guest_transport,
                cats_api::runtime_reconciliation::GuestTransportEvidence::VsockReady {
                    runtime_incarnation,
                    ..
                } if runtime_incarnation == incarnation
            );
            process_matches
                && guest_matches
                && running_network_matches(runtime, desired)
                && running_mounts_match(runtime, desired)
                && matches!(
                    runtime.warm_snapshot,
                    cats_api::runtime_reconciliation::WarmSnapshotEvidence::Absent
                )
        }
        RuntimeTarget::Cold => {
            runtime.runtime_incarnation.is_none()
                && runtime.processes.is_empty()
                && runtime.mounts.is_empty()
                && runtime.networks.is_empty()
                && matches!(
                    runtime.guest_transport,
                    cats_api::runtime_reconciliation::GuestTransportEvidence::Unavailable
                )
                && matches!(
                    runtime.warm_snapshot,
                    cats_api::runtime_reconciliation::WarmSnapshotEvidence::Absent
                )
        }
        RuntimeTarget::Warm | RuntimeTarget::Deleted => false,
    }
}

fn running_network_matches(runtime: &ObservedRuntimeStatus, desired: &DesiredRuntimeSpec) -> bool {
    runtime.networks.len() == 1
        && runtime.networks.first().is_some_and(|network| {
            network.kind == desired.runtime.network_config.kind
                && network.network_id == desired.runtime.network_config.network_id
                && network.guest_mac == desired.runtime.network_config.guest_mac
                && network.guest_ipv4 == desired.runtime.network_config.guest_ipv4
                && network.prefix_length == desired.runtime.network_config.prefix_length
                && network.gateway_ipv4 == desired.runtime.network_config.gateway_ipv4
                && matches!(
                    network.ownership_token,
                    OwnershipTokenEvidence::Valid { .. }
                )
        })
}

fn running_mounts_match(runtime: &ObservedRuntimeStatus, desired: &DesiredRuntimeSpec) -> bool {
    let expected_count = desired
        .volumes
        .iter()
        .filter(|intent| intent.mount.is_some())
        .count();
    runtime.mounts.len() == expected_count
        && desired.volumes.iter().all(|intent| match &intent.mount {
            None => !runtime
                .mounts
                .iter()
                .any(|mount| mount.volume_id == intent.volume_id),
            Some(expected) => runtime.mounts.iter().any(|mount| {
                mount.volume_id == intent.volume_id
                    && mount.guest_device == intent.guest_device
                    && mount.filesystem_uuid == expected.filesystem_uuid
                    && mount.mount_path == expected.mount_path
                    && mount.access == cats_api::runtime_reconciliation::MountAccess::ReadWrite
                    && mount.instance_count == 1
            }),
        })
}

fn routes_match(runtime: &ObservedRuntimeStatus, desired: &DesiredRuntimeSpec) -> bool {
    match desired.target {
        RuntimeTarget::Running | RuntimeTarget::Suspended => {
            let Some(incarnation) = runtime.runtime_incarnation.as_ref() else {
                return false;
            };
            runtime.routes.len() == desired.endpoints.len()
                && desired.endpoints.iter().all(|endpoint| {
                    runtime.routes.iter().any(|route| {
                        route.binding.workspace_id == desired.workspace_id
                            && route.binding.endpoint_id == endpoint.endpoint_id
                            && route.binding.hostname == endpoint.hostname
                            && route.binding.cat_id == desired.cat_id
                            && route.binding.node_id == desired.placement.node_id
                            && route.binding.runtime_incarnation == *incarnation
                            && route.binding.route_epoch == endpoint.route_epoch
                            && route.binding.protocol == endpoint.protocol
                            && route.binding.target_port == endpoint.target_port
                            && route.gate
                                == if desired.target == RuntimeTarget::Running {
                                    RouteGateState::Active
                                } else {
                                    RouteGateState::Closed
                                }
                            && (desired.target == RuntimeTarget::Running
                                || route.active_guards == 0)
                            && !route.cancellation_pending
                            && route.instance_count == 1
                    })
                })
        }
        RuntimeTarget::Cold | RuntimeTarget::Deleted => runtime.routes.is_empty(),
        RuntimeTarget::Warm => false,
    }
}

fn active_volume_evidence_matches(
    runtime: &ObservedRuntimeStatus,
    observed: &cats_api::runtime_reconciliation::ObservedVolume,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
    volume: &cats_storage::authority::VolumeRecord,
    desired: &DesiredRuntimeSpec,
) -> bool {
    let durable_generation_matches =
        |lineage: &cats_api::runtime_reconciliation::LocalVolumeLineage| {
            if desired.target == RuntimeTarget::Suspended {
                lineage.local_durable_generation == lineage.remote_durable_generation
                    && lineage.pending_pack_count.get() == 0
            } else {
                lineage.local_durable_generation >= lineage.remote_durable_generation
            }
        };
    let lineage_matches = observed.local_lineages.len() == 1
        && observed.local_lineages.first().is_some_and(|lineage| {
            lineage.attachment_id == intent.attachment_id
                && lineage.attachment_epoch == volume.lease_epoch
                && acquire_origin_matches(&lineage.acquire_origin, &intent.acquire)
                && lineage.node_id == desired.placement.node_id
                && lineage.placement_epoch == desired.placement.placement_epoch
                && lineage.remote_durable_generation == volume.head.generation
                && durable_generation_matches(lineage)
                && !lineage.fenced
                && lineage.state == LocalLineageState::Active
        });
    let devices_match = observed.devices.len() == 1
        && observed.devices.first().is_some_and(|device| match device {
            cats_api::runtime_reconciliation::ObservedDevice::KernelNbd {
                guest_device,
                ownership_token,
                ..
            }
            | cats_api::runtime_reconciliation::ObservedDevice::VhostUserBlk {
                guest_device,
                ownership_token,
                ..
            } => {
                guest_device == &intent.guest_device
                    && matches!(ownership_token, OwnershipTokenEvidence::Valid { .. })
            }
        });
    let blockd_count = runtime
        .processes
        .iter()
        .filter(|process| {
            matches!(
                &process.role,
                ProcessRole::Blockd {
                    volume_id,
                    attachment_id,
                    attachment_epoch,
                } if volume_id == &intent.volume_id
                    && attachment_id == &intent.attachment_id
                    && attachment_epoch == &volume.lease_epoch
            ) && process.state == ProcessState::Running
                && matches!(
                    process.ownership_token,
                    OwnershipTokenEvidence::Valid { .. }
                )
                && matches!(
                    process.control_handshake,
                    cats_api::runtime_reconciliation::ControlHandshakeEvidence::Verified
                )
        })
        .count();
    lineage_matches
        && devices_match
        && blockd_count == 1
        && runtime.processes.len() == desired.volumes.len() + 1
}

fn cold_volume_evidence_matches(
    observed: &cats_api::runtime_reconciliation::ObservedVolume,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
    volume: &cats_storage::authority::VolumeRecord,
    desired: &DesiredRuntimeSpec,
) -> bool {
    observed.devices.is_empty()
        && observed.local_lineages.len() == 1
        && observed.local_lineages.first().is_some_and(|lineage| {
            lineage.attachment_id == intent.attachment_id
                && lineage.attachment_epoch == volume.lease_epoch
                && acquire_origin_matches(&lineage.acquire_origin, &intent.acquire)
                && lineage.node_id == desired.placement.node_id
                && lineage.placement_epoch == desired.placement.placement_epoch
                && lineage.local_durable_generation == volume.head.generation
                && lineage.remote_durable_generation == volume.head.generation
                && lineage.pending_pack_count.get() == 0
                && lineage.fenced
                && lineage.state == LocalLineageState::Released
        })
}

fn acquire_origin_matches(
    observed: &cats_api::runtime_reconciliation::AcquireOrigin,
    desired: &cats_api::runtime_reconciliation::VolumeAcquire,
) -> bool {
    matches!(
        (observed, desired),
        (
            cats_api::runtime_reconciliation::AcquireOrigin::Normal {
                transition_id: observed,
            },
            cats_api::runtime_reconciliation::VolumeAcquire::Normal {
                transition_id: desired,
                ..
            }
        ) if observed == desired
    ) || matches!(
        (observed, desired),
        (
            cats_api::runtime_reconciliation::AcquireOrigin::Takeover {
                authorization_id: observed,
            },
            cats_api::runtime_reconciliation::VolumeAcquire::Takeover {
                authorization_id: desired,
            }
        ) if observed == desired
    )
}

fn deleted_postcondition_satisfied(
    transaction: &mut Transaction<'_>,
    runtime: &ObservedRuntimeStatus,
    desired: &DesiredRuntimeSpec,
) -> AuthorityTxResult<bool> {
    if runtime.runtime_incarnation.is_some()
        || !runtime.processes.is_empty()
        || !runtime.volumes.is_empty()
        || !runtime.mounts.is_empty()
        || !runtime.networks.is_empty()
        || !runtime.routes.is_empty()
        || !matches!(
            runtime.guest_transport,
            cats_api::runtime_reconciliation::GuestTransportEvidence::Unavailable
        )
        || !matches!(
            runtime.warm_snapshot,
            cats_api::runtime_reconciliation::WarmSnapshotEvidence::Absent
        )
    {
        return Ok(false);
    }
    for intent in &desired.volumes {
        match &intent.disposition {
            cats_api::runtime_reconciliation::VolumeDisposition::DeleteDisposableRoot {
                delete_id,
            } => {
                if load_disk_by_id_for_update(transaction, &intent.disk_id)?.is_some()
                    || load_volume_for_update(transaction, &intent.volume_id)?.is_some()
                {
                    return Ok(false);
                }
                let Some(receipt) = load_delete_completion_for_update(transaction, delete_id)?
                else {
                    return Ok(false);
                };
                let identity_matches = match receipt {
                    DeleteCompletionReceipt::Normal { request, .. } => {
                        request.delete_id == *delete_id
                            && request.disk_id == intent.disk_id
                            && request.volume_id == intent.volume_id
                    }
                    DeleteCompletionReceipt::DisposableRoot {
                        disk_id,
                        volume_id,
                        delete_id: receipt_delete_id,
                        ..
                    } => {
                        disk_id == intent.disk_id
                            && volume_id == intent.volume_id
                            && receipt_delete_id == *delete_id
                    }
                };
                if !identity_matches {
                    return Ok(false);
                }
            }
            cats_api::runtime_reconciliation::VolumeDisposition::Retain
            | cats_api::runtime_reconciliation::VolumeDisposition::DetachRetained => {
                let Some(disk) = load_disk_by_id_for_update(transaction, &intent.disk_id)? else {
                    return Ok(false);
                };
                let Some(volume) = load_volume_for_update(transaction, &intent.volume_id)? else {
                    return Ok(false);
                };
                if !matches!(disk.admin_state, DiskAdminState::Active)
                    || !matches!(volume.admin_state, VolumeAdminState::Active)
                    || volume.lease_owner.is_some()
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn authority_projection(volume: &cats_storage::authority::VolumeRecord) -> VolumeAuthorityEvidence {
    match &volume.admin_state {
        VolumeAdminState::Deleting { delete_id } => VolumeAuthorityEvidence::Deleting {
            delete_id: delete_id.clone(),
            attachment_epoch: volume.lease_epoch,
            head: volume.head.clone(),
        },
        VolumeAdminState::Active => match &volume.lease_owner {
            Some(attachment_id) => VolumeAuthorityEvidence::Owned {
                attachment_id: attachment_id.clone(),
                attachment_epoch: volume.lease_epoch,
                head: volume.head.clone(),
            },
            None => VolumeAuthorityEvidence::Unowned {
                attachment_epoch: volume.lease_epoch,
                head: volume.head.clone(),
            },
        },
    }
}

fn durability_matches(
    desired: cats_api::runtime_reconciliation::Durability,
    stored: VolumeDurability,
) -> bool {
    matches!(
        (desired, stored),
        (
            cats_api::runtime_reconciliation::Durability::Strict,
            VolumeDurability::Strict
        ) | (
            cats_api::runtime_reconciliation::Durability::Relaxed,
            VolumeDurability::Relaxed
        )
    )
}

fn disk_kind_matches(
    desired: cats_api::runtime_reconciliation::DiskKind,
    stored: &DiskRole,
    cat_id: &Id,
) -> bool {
    matches!(
        (desired, stored),
        (
            cats_api::runtime_reconciliation::DiskKind::Root,
            DiskRole::Root { cat_id: root_cat_id }
        ) if root_cat_id == cat_id
    ) || matches!(
        (desired, stored),
        (
            cats_api::runtime_reconciliation::DiskKind::Persistent,
            DiskRole::Persistent { .. }
        )
    )
}

fn observed_disk_kind_matches(
    desired: cats_api::runtime_reconciliation::DiskKind,
    observed: ObservedDiskKind,
) -> bool {
    matches!(
        (desired, observed),
        (
            cats_api::runtime_reconciliation::DiskKind::Root,
            ObservedDiskKind::Root
        ) | (
            cats_api::runtime_reconciliation::DiskKind::Persistent,
            ObservedDiskKind::Persistent
        )
    )
}

fn load_observation_receive_state_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<ObservationReceiveState>> {
    transaction
        .query_opt(
            "SELECT observation::text AS observation_json,
                    acceptance::text AS acceptance_json, node_id, node_boot_id,
                    agent_instance_id, agent_session_epoch, heartbeat_sequence,
                    observation_id, accepted_at_unix_ms
               FROM runtime_observation_receive_states
              WHERE node_id=$1 FOR UPDATE",
            &[&node_id.as_str()],
        )?
        .map(|row| decode_observation_receive_state(&row))
        .transpose()
}

fn decode_observation_receive_state(row: &Row) -> AuthorityTxResult<ObservationReceiveState> {
    let observation_json: String = row.try_get("observation_json")?;
    let acceptance_json: String = row.try_get("acceptance_json")?;
    let observation = decode_node_observation(observation_json.as_bytes()).map_err(corrupt)?;
    let acceptance = decode_observation_acceptance(acceptance_json.as_bytes()).map_err(corrupt)?;
    let node_id: String = row.try_get("node_id")?;
    let node_boot_id: String = row.try_get("node_boot_id")?;
    let agent_instance_id: String = row.try_get("agent_instance_id")?;
    let epoch: Epoch = from_pg(row.try_get("agent_session_epoch")?)?;
    let sequence: Sequence = from_pg(row.try_get("heartbeat_sequence")?)?;
    let observation_id: String = row.try_get("observation_id")?;
    let accepted_at: UnixMillis = from_pg(row.try_get("accepted_at_unix_ms")?)?;
    let inventory_matches = match (&acceptance.inventory, observation.complete_inventory) {
        (ObservationInventoryAcceptance::Full { attestation }, true) => {
            attestation.node_id == observation.node_id
                && attestation.agent_session_epoch == observation.agent_session_epoch
                && attestation.inventory_epoch == observation.inventory_epoch
                && observation.inventory_digest.as_ref() == Some(&attestation.inventory_digest)
                && observation.inventory_read_position == Some(attestation.inventory_read_position)
                && attestation.accepted_at_unix_ms == acceptance.accepted_at_unix_ms
        }
        (ObservationInventoryAcceptance::Partial { inventory_epoch }, false) => {
            *inventory_epoch == observation.inventory_epoch
        }
        _ => false,
    };
    if observation.node_id.as_str() != node_id
        || observation.node_boot_id.as_str() != node_boot_id
        || observation.agent_instance_id.as_str() != agent_instance_id
        || observation.agent_session_epoch != epoch
        || observation.heartbeat_sequence != sequence
        || observation.observation_id.as_str() != observation_id
        || acceptance.session != observation_binding(&observation)
        || acceptance.observation_id != observation.observation_id
        || acceptance.heartbeat_sequence != observation.heartbeat_sequence
        || acceptance.accepted_at_unix_ms != accepted_at
        || !inventory_matches
    {
        return Err(corrupt(
            "observation receive-state JSON/projection mismatch",
        ));
    }
    Ok(ObservationReceiveState {
        observation,
        acceptance,
    })
}

fn upsert_observation_receive_state(
    transaction: &mut Transaction<'_>,
    state: &ObservationReceiveState,
) -> AuthorityTxResult<()> {
    let observation =
        String::from_utf8(encode_node_observation(&state.observation).map_err(corrupt)?)
            .map_err(corrupt)?;
    let acceptance =
        String::from_utf8(encode_observation_acceptance(&state.acceptance).map_err(corrupt)?)
            .map_err(corrupt)?;
    let epoch = state
        .observation
        .agent_session_epoch
        .to_pg()
        .map_err(corrupt)?;
    let sequence = state
        .observation
        .heartbeat_sequence
        .to_pg()
        .map_err(corrupt)?;
    let accepted_at = state
        .acceptance
        .accepted_at_unix_ms
        .to_pg()
        .map_err(corrupt)?;
    transaction.execute(
        "INSERT INTO runtime_observation_receive_states (
            node_id, observation, acceptance, node_boot_id,
            agent_instance_id, agent_session_epoch, heartbeat_sequence,
            observation_id, accepted_at_unix_ms
         ) VALUES ($1,$2::TEXT::jsonb,$3::TEXT::jsonb,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (node_id) DO UPDATE SET
            observation=EXCLUDED.observation, acceptance=EXCLUDED.acceptance,
            node_boot_id=EXCLUDED.node_boot_id,
            agent_instance_id=EXCLUDED.agent_instance_id,
            agent_session_epoch=EXCLUDED.agent_session_epoch,
            heartbeat_sequence=EXCLUDED.heartbeat_sequence,
            observation_id=EXCLUDED.observation_id,
            accepted_at_unix_ms=EXCLUDED.accepted_at_unix_ms",
        &[
            &state.observation.node_id.as_str(),
            &observation,
            &acceptance,
            &state.observation.node_boot_id.as_str(),
            &state.observation.agent_instance_id.as_str(),
            &epoch,
            &sequence,
            &state.observation.observation_id.as_str(),
            &accepted_at,
        ],
    )?;
    Ok(())
}

fn load_admission_inventory_state_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<AdmissionInventoryState>> {
    transaction
        .query_opt(
            "SELECT attestation::text AS attestation_json,
                    full_observation::text AS observation_json,
                    assigned_snapshot::text AS snapshot_json,
                    node_id, node_boot_id, agent_instance_id,
                    agent_session_epoch, inventory_epoch, inventory_digest,
                    inventory_read_position, accepted_at_unix_ms
               FROM runtime_admission_inventory_states
              WHERE node_id=$1 FOR UPDATE",
            &[&node_id.as_str()],
        )?
        .map(|row| decode_admission_inventory_state(&row))
        .transpose()
}

fn load_admission_inventory_state_unlocked(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<AdmissionInventoryState>> {
    transaction
        .query_opt(
            "SELECT attestation::text AS attestation_json,
                    full_observation::text AS observation_json,
                    assigned_snapshot::text AS snapshot_json,
                    node_id, node_boot_id, agent_instance_id,
                    agent_session_epoch, inventory_epoch, inventory_digest,
                    inventory_read_position, accepted_at_unix_ms
               FROM runtime_admission_inventory_states WHERE node_id=$1",
            &[&node_id.as_str()],
        )?
        .map(|row| decode_admission_inventory_state(&row))
        .transpose()
}

fn decode_admission_inventory_state(row: &Row) -> AuthorityTxResult<AdmissionInventoryState> {
    let attestation_json: String = row.try_get("attestation_json")?;
    let observation_json: String = row.try_get("observation_json")?;
    let snapshot_json: String = row.try_get("snapshot_json")?;
    let attestation =
        decode_admission_inventory_attestation(attestation_json.as_bytes()).map_err(corrupt)?;
    let full_observation = decode_node_observation(observation_json.as_bytes()).map_err(corrupt)?;
    let assigned_snapshot =
        decode_desired_read_snapshot(snapshot_json.as_bytes()).map_err(corrupt)?;
    let node_id: String = row.try_get("node_id")?;
    let node_boot_id: String = row.try_get("node_boot_id")?;
    let agent_instance_id: String = row.try_get("agent_instance_id")?;
    let epoch: Epoch = from_pg(row.try_get("agent_session_epoch")?)?;
    let inventory_epoch: Epoch = from_pg(row.try_get("inventory_epoch")?)?;
    let inventory_digest: String = row.try_get("inventory_digest")?;
    let inventory_read_position: Sequence = from_pg(row.try_get("inventory_read_position")?)?;
    let accepted_at: UnixMillis = from_pg(row.try_get("accepted_at_unix_ms")?)?;
    let binding = observation_binding(&full_observation);
    if !full_observation.complete_inventory
        || binding.node_id.as_str() != node_id
        || binding.node_boot_id.as_str() != node_boot_id
        || binding.agent_instance_id.as_str() != agent_instance_id
        || binding.agent_session_epoch != epoch
        || assigned_snapshot.session != binding
        || assigned_snapshot.read_position != inventory_read_position
        || attestation.node_id != binding.node_id
        || attestation.agent_session_epoch != epoch
        || attestation.inventory_epoch != inventory_epoch
        || attestation.inventory_digest.as_str() != inventory_digest
        || attestation.inventory_read_position != inventory_read_position
        || attestation.accepted_at_unix_ms != accepted_at
        || full_observation.inventory_epoch != inventory_epoch
        || full_observation.inventory_digest.as_ref() != Some(&attestation.inventory_digest)
        || full_observation.inventory_read_position != Some(inventory_read_position)
    {
        return Err(corrupt(
            "admission inventory state binding/projection mismatch",
        ));
    }
    if assigned_snapshot.issued_at_unix_ms > accepted_at
        || accepted_at >= assigned_snapshot.expires_at_unix_ms
    {
        return Err(corrupt(
            "admission inventory cursor/acceptance causality mismatch",
        ));
    }
    Ok(AdmissionInventoryState {
        attestation,
        full_observation,
        assigned_snapshot,
    })
}

fn upsert_admission_inventory_state(
    transaction: &mut Transaction<'_>,
    state: &AdmissionInventoryState,
) -> AuthorityTxResult<()> {
    let attestation = String::from_utf8(
        encode_admission_inventory_attestation(&state.attestation).map_err(corrupt)?,
    )
    .map_err(corrupt)?;
    let observation =
        String::from_utf8(encode_node_observation(&state.full_observation).map_err(corrupt)?)
            .map_err(corrupt)?;
    let snapshot =
        String::from_utf8(encode_desired_read_snapshot(&state.assigned_snapshot).map_err(corrupt)?)
            .map_err(corrupt)?;
    let epoch = state
        .full_observation
        .agent_session_epoch
        .to_pg()
        .map_err(corrupt)?;
    let inventory_epoch = state.attestation.inventory_epoch.to_pg().map_err(corrupt)?;
    let position = state
        .attestation
        .inventory_read_position
        .to_pg()
        .map_err(corrupt)?;
    let accepted_at = state
        .attestation
        .accepted_at_unix_ms
        .to_pg()
        .map_err(corrupt)?;
    transaction.execute(
        "INSERT INTO runtime_admission_inventory_states (
            node_id, attestation, full_observation, assigned_snapshot,
            node_boot_id, agent_instance_id, agent_session_epoch,
            inventory_epoch, inventory_digest, inventory_read_position,
            accepted_at_unix_ms
         ) VALUES ($1,$2::TEXT::jsonb,$3::TEXT::jsonb,$4::TEXT::jsonb,
                   $5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (node_id) DO UPDATE SET
            attestation=EXCLUDED.attestation,
            full_observation=EXCLUDED.full_observation,
            assigned_snapshot=EXCLUDED.assigned_snapshot,
            node_boot_id=EXCLUDED.node_boot_id,
            agent_instance_id=EXCLUDED.agent_instance_id,
            agent_session_epoch=EXCLUDED.agent_session_epoch,
            inventory_epoch=EXCLUDED.inventory_epoch,
            inventory_digest=EXCLUDED.inventory_digest,
            inventory_read_position=EXCLUDED.inventory_read_position,
            accepted_at_unix_ms=EXCLUDED.accepted_at_unix_ms",
        &[
            &state.full_observation.node_id.as_str(),
            &attestation,
            &observation,
            &snapshot,
            &state.full_observation.node_boot_id.as_str(),
            &state.full_observation.agent_instance_id.as_str(),
            &epoch,
            &inventory_epoch,
            &state.attestation.inventory_digest.as_str(),
            &position,
            &accepted_at,
        ],
    )?;
    Ok(())
}

fn replace_full_cat_observations(
    transaction: &mut Transaction<'_>,
    observation: &NodeObservation,
    accepted_at: UnixMillis,
) -> AuthorityTxResult<()> {
    transaction.execute(
        "DELETE FROM runtime_current_cat_observations WHERE node_id=$1",
        &[&observation.node_id.as_str()],
    )?;
    for runtime in &observation.runtimes {
        upsert_cat_observation(transaction, observation, runtime, accepted_at, "full")?;
    }
    Ok(())
}

fn upsert_partial_cat_observations(
    transaction: &mut Transaction<'_>,
    observation: &NodeObservation,
    accepted_at: UnixMillis,
) -> AuthorityTxResult<()> {
    for runtime in &observation.runtimes {
        upsert_cat_observation(transaction, observation, runtime, accepted_at, "partial")?;
    }
    Ok(())
}

fn load_current_cat_observation(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    cat_id: &Id,
) -> AuthorityTxResult<Option<CurrentCatObservation>> {
    let Some(row) = transaction.query_opt(
        "SELECT runtime_record::text AS runtime_json, node_id, cat_id,
                node_boot_id, agent_instance_id, agent_session_epoch,
                inventory_epoch, source_observation_id, heartbeat_sequence,
                accepted_at_unix_ms, source_kind
           FROM runtime_current_cat_observations
          WHERE node_id=$1 AND cat_id=$2",
        &[&node_id.as_str(), &cat_id.as_str()],
    )?
    else {
        return Ok(None);
    };
    let runtime_json: String = row.try_get("runtime_json")?;
    let runtime: ObservedRuntimeStatus = serde_json::from_str(&runtime_json).map_err(corrupt)?;
    let projected_node_id =
        Id::new(row.try_get::<_, String>("node_id")?).ok_or_else(|| corrupt("invalid Node ID"))?;
    let projected_cat_id =
        Id::new(row.try_get::<_, String>("cat_id")?).ok_or_else(|| corrupt("invalid Cat ID"))?;
    let session = SessionBinding {
        node_id: projected_node_id,
        node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
            row.try_get::<_, String>("node_boot_id")?,
        )
        .ok_or_else(|| corrupt("invalid stored Node boot ID"))?,
        agent_instance_id: RandomId128::new(row.try_get::<_, String>("agent_instance_id")?)
            .ok_or_else(|| corrupt("invalid stored Agent instance ID"))?,
        agent_session_epoch: from_pg(row.try_get("agent_session_epoch")?)?,
    };
    let inventory_epoch = from_pg(row.try_get("inventory_epoch")?)?;
    let source_observation_id =
        RandomId128::new(row.try_get::<_, String>("source_observation_id")?)
            .ok_or_else(|| corrupt("invalid stored observation ID"))?;
    let heartbeat_sequence = from_pg(row.try_get("heartbeat_sequence")?)?;
    let accepted_at_unix_ms = from_pg(row.try_get("accepted_at_unix_ms")?)?;
    let source_kind = match row.try_get::<_, String>("source_kind")?.as_str() {
        "full" => ObservationSourceKind::Full,
        "partial" => ObservationSourceKind::Partial,
        _ => return Err(corrupt("invalid per-Cat observation source kind")),
    };
    if runtime.cat_id != projected_cat_id {
        return Err(corrupt("per-Cat runtime JSON/projection mismatch"));
    }
    Ok(Some(CurrentCatObservation {
        runtime,
        session,
        inventory_epoch,
        source_observation_id,
        heartbeat_sequence,
        accepted_at_unix_ms,
        source_kind,
    }))
}

fn upsert_cat_observation(
    transaction: &mut Transaction<'_>,
    observation: &NodeObservation,
    runtime: &ObservedRuntimeStatus,
    accepted_at: UnixMillis,
    source_kind: &'static str,
) -> AuthorityTxResult<()> {
    let runtime_json = serde_json::to_string(runtime).map_err(corrupt)?;
    let epoch = observation.agent_session_epoch.to_pg().map_err(corrupt)?;
    let inventory_epoch = observation.inventory_epoch.to_pg().map_err(corrupt)?;
    let sequence = observation.heartbeat_sequence.to_pg().map_err(corrupt)?;
    let accepted_at = accepted_at.to_pg().map_err(corrupt)?;
    transaction.execute(
        "INSERT INTO runtime_current_cat_observations (
            node_id, cat_id, runtime_record, node_boot_id,
            agent_instance_id, agent_session_epoch, inventory_epoch,
            source_observation_id, heartbeat_sequence, accepted_at_unix_ms,
            source_kind
         ) VALUES ($1,$2,$3::TEXT::jsonb,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (node_id,cat_id) DO UPDATE SET
            runtime_record=EXCLUDED.runtime_record,
            node_boot_id=EXCLUDED.node_boot_id,
            agent_instance_id=EXCLUDED.agent_instance_id,
            agent_session_epoch=EXCLUDED.agent_session_epoch,
            inventory_epoch=EXCLUDED.inventory_epoch,
            source_observation_id=EXCLUDED.source_observation_id,
            heartbeat_sequence=EXCLUDED.heartbeat_sequence,
            accepted_at_unix_ms=EXCLUDED.accepted_at_unix_ms,
            source_kind=EXCLUDED.source_kind",
        &[
            &observation.node_id.as_str(),
            &runtime.cat_id.as_str(),
            &runtime_json,
            &observation.node_boot_id.as_str(),
            &observation.agent_instance_id.as_str(),
            &epoch,
            &inventory_epoch,
            &observation.observation_id.as_str(),
            &sequence,
            &accepted_at,
            &source_kind,
        ],
    )?;
    Ok(())
}
