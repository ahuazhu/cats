//! One read-only, repeatable-read fleet snapshot for the cutover verifier.

use std::collections::BTreeMap;

use cats_api::fleet_verification::{
    FleetRouteSigningAuthority, FleetVerificationInventory, FleetVerificationNode,
    FleetVerificationSnapshot, FLEET_VERIFICATION_MAX_NODES,
};
use cats_api::route_grant_v2::RouteGrantV2SignerSelection;
use cats_api::runtime_reconciliation::{
    Condition, ContractVersion, Id, LifecycleAdmission, NodeIdentityState, NodeResidue,
    RouteGateState, SessionBinding, Sha256Digest, WireU64,
};
use cats_storage::authority::AuthorityError;
use postgres::Transaction;

use super::route_signing_authority::load_current_signer;
use super::rows::database_now;
use super::runtime_spine::load_admission_inventory_state_unlocked;
use crate::store::agent_sessions::{
    load_all_identities_for_fleet_verification, load_current_session_unlocked,
};
use crate::store::transaction::{
    AuthorityRequestContext, AuthorityTransactionError, AuthorityTxResult,
};
use crate::store::{Result, Store};

impl Store {
    pub(crate) fn fleet_verification_snapshot(
        &self,
        request: &AuthorityRequestContext,
        approved_guest_config_digest: &Sha256Digest,
    ) -> Result<FleetVerificationSnapshot> {
        self.authority_request_read_snapshot(request, |transaction| {
            fleet_verification_snapshot_in(transaction, approved_guest_config_digest)
        })
    }
}

fn fleet_verification_snapshot_in(
    transaction: &mut Transaction<'_>,
    approved_guest_config_digest: &Sha256Digest,
) -> AuthorityTxResult<FleetVerificationSnapshot> {
    let query_limit = i64::try_from(FLEET_VERIFICATION_MAX_NODES + 1).map_err(corrupt)?;
    let identities = load_all_identities_for_fleet_verification(transaction, query_limit)?;
    if identities.len() > FLEET_VERIFICATION_MAX_NODES {
        return Err(corrupt("fleet verification NodeIdentity bound exceeded"));
    }
    let identity_states = identities
        .iter()
        .map(|identity| (identity.node_id.clone(), identity.state))
        .collect::<BTreeMap<_, _>>();
    validate_child_node_keys(
        transaction,
        ChildNodeTable::CurrentSessions,
        &identity_states,
        query_limit,
    )?;
    validate_child_node_keys(
        transaction,
        ChildNodeTable::AdmissionInventories,
        &identity_states,
        query_limit,
    )?;

    let mut nodes = Vec::new();
    for identity in identities {
        let session = load_current_session_unlocked(transaction, &identity.node_id)?;
        if identity.state == NodeIdentityState::Retired {
            if session.is_some()
                || load_admission_inventory_state_unlocked(transaction, &identity.node_id)?
                    .is_some()
            {
                return Err(corrupt(
                    "retired NodeIdentity retains current session or admission inventory",
                ));
            }
            continue;
        }
        if identity.state != NodeIdentityState::Provisioned {
            return Err(corrupt("NodeIdentity has an unknown state"));
        }
        let inventory = load_admission_inventory_state_unlocked(transaction, &identity.node_id)?
            .map(summarize_inventory)
            .transpose()?;
        nodes.push(FleetVerificationNode {
            node_id: identity.node_id,
            session,
            inventory,
        });
    }

    let desired_runtime_count: i64 = transaction
        .query_one("SELECT count(*) FROM desired_runtime_specs", &[])?
        .try_get(0)?;
    let desired_runtime_count = u64::try_from(desired_runtime_count)
        .ok()
        .and_then(WireU64::new)
        .ok_or_else(|| corrupt("desired runtime count is outside the wire range"))?;
    let current_runtime_observation_count: i64 = transaction
        .query_one("SELECT count(*) FROM runtime_current_cat_observations", &[])?
        .try_get(0)?;
    let current_runtime_observation_count = u64::try_from(current_runtime_observation_count)
        .ok()
        .and_then(WireU64::new)
        .ok_or_else(|| corrupt("current runtime observation count is outside the wire range"))?;

    let route_signing_authority = load_current_signer(transaction, "")?.map(|binding| {
        let reference = binding.reference();
        let active_kid = match &reference.signer {
            RouteGrantV2SignerSelection::Disabled => None,
            RouteGrantV2SignerSelection::Active { active_kid, .. } => Some(active_kid.clone()),
        };
        FleetRouteSigningAuthority {
            deployment_id: reference.deployment_id.clone(),
            signer_revision: reference.signer_revision,
            signer_reference_sha256: binding.reference_sha256().clone(),
            active_kid,
            public_key_ring_version: reference.public_key_ring_version,
            public_key_ring_digest: reference.public_key_ring_digest.clone(),
        }
    });
    // Capture the sole evaluation clock after the complete facts load. A
    // lease or attestation that expires while this bounded snapshot is being
    // assembled must not be represented as live at an earlier start time.
    let evaluated_at_unix_ms = database_now(transaction)?;

    Ok(FleetVerificationSnapshot {
        version: ContractVersion::V1,
        control_release_commit_sha: option_env!("CATS_RELEASE_COMMIT_SHA").map(str::to_owned),
        evaluated_at_unix_ms,
        approved_guest_config_digest: approved_guest_config_digest.clone(),
        desired_runtime_count,
        current_runtime_observation_count,
        route_signing_authority,
        nodes,
    })
}

#[derive(Clone, Copy)]
enum ChildNodeTable {
    CurrentSessions,
    AdmissionInventories,
}

fn validate_child_node_keys(
    transaction: &mut Transaction<'_>,
    table: ChildNodeTable,
    identity_states: &BTreeMap<Id, NodeIdentityState>,
    query_limit: i64,
) -> AuthorityTxResult<()> {
    let sql = match table {
        ChildNodeTable::CurrentSessions => {
            "SELECT node_id FROM current_agent_sessions ORDER BY node_id COLLATE \"C\" LIMIT $1"
        }
        ChildNodeTable::AdmissionInventories => {
            "SELECT node_id FROM runtime_admission_inventory_states ORDER BY node_id COLLATE \"C\" LIMIT $1"
        }
    };
    let rows = transaction.query(sql, &[&query_limit])?;
    if rows.len() > FLEET_VERIFICATION_MAX_NODES {
        return Err(corrupt("fleet verification child-row bound exceeded"));
    }
    for row in rows {
        let raw: String = row.try_get("node_id")?;
        let node_id = Id::new(raw).ok_or_else(|| corrupt("child row has an invalid Node ID"))?;
        if identity_states.get(&node_id) != Some(&NodeIdentityState::Provisioned) {
            return Err(corrupt(
                "current session/inventory row does not belong to a provisioned identity",
            ));
        }
    }
    Ok(())
}

fn summarize_inventory(
    state: super::runtime_spine::AdmissionInventoryState,
) -> AuthorityTxResult<FleetVerificationInventory> {
    let observation = &state.full_observation;
    let mut lifecycle_open_count = 0_u64;
    let mut route_active_count = 0_u64;
    let mut route_closed_count = 0_u64;
    let mut active_guard_count = 0_u64;
    let mut cancellation_pending_count = 0_u64;
    let mut quarantined_condition_count = 0_u64;

    for runtime in &observation.runtimes {
        if runtime.lifecycle_admission == LifecycleAdmission::Open {
            checked_increment(&mut lifecycle_open_count)?;
        }
        checked_add(&mut active_guard_count, u64::from(runtime.platform_guards))?;
        for route in &runtime.routes {
            count_gate(
                route.gate,
                route.active_guards,
                route.cancellation_pending,
                route.instance_count,
                &mut route_active_count,
                &mut route_closed_count,
                &mut active_guard_count,
                &mut cancellation_pending_count,
            )?;
        }
        for condition in &runtime.conditions {
            if matches!(condition, Condition::Quarantined { .. }) {
                checked_increment(&mut quarantined_condition_count)?;
            }
        }
    }
    for residue in &observation.residue {
        if let NodeResidue::RouteGate {
            gate,
            active_guards,
            cancellation_pending,
            instance_count,
            ..
        } = residue
        {
            count_gate(
                *gate,
                *active_guards,
                *cancellation_pending,
                *instance_count,
                &mut route_active_count,
                &mut route_closed_count,
                &mut active_guard_count,
                &mut cancellation_pending_count,
            )?;
        }
    }

    Ok(FleetVerificationInventory {
        source_session: SessionBinding {
            node_id: observation.node_id.clone(),
            node_boot_id: observation.node_boot_id.clone(),
            agent_instance_id: observation.agent_instance_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
        },
        attestation: state.attestation,
        source_observation_id: observation.observation_id.clone(),
        source_heartbeat_sequence: observation.heartbeat_sequence,
        source_observed_at_unix_ms: observation.observed_at_unix_ms,
        complete_inventory: observation.complete_inventory,
        assigned_desired_count: wire_count(state.assigned_snapshot.desired_specs.len())?,
        runtime_count: wire_count(observation.runtimes.len())?,
        residue_count: wire_count(observation.residue.len())?,
        lifecycle_open_count: wire(lifecycle_open_count)?,
        route_active_count: wire(route_active_count)?,
        route_closed_count: wire(route_closed_count)?,
        active_guard_count: wire(active_guard_count)?,
        cancellation_pending_count: wire(cancellation_pending_count)?,
        quarantined_condition_count: wire(quarantined_condition_count)?,
        key_ring_version: observation.key_ring_version,
        key_ring_digest: observation.key_ring_digest.clone(),
        loaded_kids: observation.loaded_kids.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn count_gate(
    gate: RouteGateState,
    active_guards: u32,
    cancellation_pending: bool,
    instance_count: u64,
    route_active_count: &mut u64,
    route_closed_count: &mut u64,
    active_guard_count: &mut u64,
    cancellation_pending_count: &mut u64,
) -> AuthorityTxResult<()> {
    match gate {
        RouteGateState::Active => checked_add(route_active_count, instance_count)?,
        RouteGateState::Closed => checked_add(route_closed_count, instance_count)?,
    }
    checked_add(active_guard_count, u64::from(active_guards))?;
    if cancellation_pending {
        checked_increment(cancellation_pending_count)?;
    }
    Ok(())
}

fn wire_count(value: usize) -> AuthorityTxResult<WireU64> {
    u64::try_from(value)
        .ok()
        .and_then(WireU64::new)
        .ok_or_else(|| corrupt("fleet verification count is outside the wire range"))
}

fn wire(value: u64) -> AuthorityTxResult<WireU64> {
    WireU64::new(value).ok_or_else(|| corrupt("fleet verification count is outside the wire range"))
}

fn checked_increment(value: &mut u64) -> AuthorityTxResult<()> {
    checked_add(value, 1)
}

fn checked_add(value: &mut u64, addend: u64) -> AuthorityTxResult<()> {
    *value = value
        .checked_add(addend)
        .ok_or_else(|| corrupt("fleet verification counter overflow"))?;
    Ok(())
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    AuthorityError::BackendUnknown.into()
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{
        ContractVersion, CredentialBinding, Id, NodeIdentity, NodeIdentityState, Sha256Digest,
    };

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn identity(suffix: &str, digest_byte: u8) -> NodeIdentity {
        NodeIdentity {
            version: ContractVersion::V1,
            node_id: id(&format!("node_{suffix}")),
            immutable_host_id: id(&format!("host_{suffix}")),
            credential_id: id(&format!("credential_{suffix}")),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: Sha256Digest::from_bytes([digest_byte; 32]),
            },
            state_path_id: id(&format!("state_{suffix}")),
            state: NodeIdentityState::Provisioned,
        }
    }

    fn request() -> AuthorityRequestContext {
        AuthorityRequestContext::new(Instant::now() + Duration::from_secs(10))
    }

    #[test]
    fn fleet_snapshot_keeps_one_repeatable_read_membership_under_concurrent_provision() {
        let url = crate::testsupport::isolated_control_store_url();
        let reader = Store::connect(&url, None).unwrap();
        let writer = Store::connect(&url, None).unwrap();
        reader.provision_node_identity(&identity("a", 1)).unwrap();
        let approved = Sha256Digest::from_bytes([9; 32]);
        let (entered_send, entered_receive) = mpsc::channel();
        let (continue_send, continue_receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            reader
                .authority_read_snapshot(move |transaction| {
                    let first = load_all_identities_for_fleet_verification(transaction, 2)?;
                    assert_eq!(first.len(), 1);
                    entered_send.send(()).unwrap();
                    continue_receive.recv().unwrap();
                    let snapshot = fleet_verification_snapshot_in(transaction, &approved)?;
                    assert_eq!(
                        snapshot
                            .nodes
                            .iter()
                            .map(|node| node.node_id.as_str())
                            .collect::<Vec<_>>(),
                        vec!["node_a"]
                    );
                    Ok(())
                })
                .unwrap();
        });
        entered_receive.recv().unwrap();
        writer.provision_node_identity(&identity("b", 2)).unwrap();
        continue_send.send(()).unwrap();
        worker.join().unwrap();
        assert_eq!(
            writer
                .fleet_verification_snapshot(&request(), &Sha256Digest::from_bytes([9; 32]))
                .unwrap()
                .nodes
                .len(),
            2
        );
    }

    #[test]
    fn fleet_snapshot_does_not_hide_a_corrupt_identity_behind_state_filtering() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        store.provision_node_identity(&identity("a", 1)).unwrap();
        store
            .with(|client| {
                client.batch_execute(
                    "ALTER TABLE node_identities DROP CONSTRAINT
                            node_identity_current_public_key_lineage;
                         UPDATE node_identities
                            SET state='retired', credential_lineage_state='retired'
                          WHERE node_id='node_a';",
                )
            })
            .unwrap();
        assert!(store
            .fleet_verification_snapshot(&request(), &Sha256Digest::from_bytes([9; 32]))
            .is_err());
    }
}
