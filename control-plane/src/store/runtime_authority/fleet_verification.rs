//! One read-only, repeatable-read fleet snapshot for the cutover verifier.

use cats_api::fleet_verification::{
    FleetRouteSigningAuthority, FleetVerificationInventory, FleetVerificationNode,
    FleetVerificationSnapshot,
};
use cats_api::route_grant_v2::RouteGrantV2SignerSelection;
use cats_api::runtime_reconciliation::{
    Condition, ContractVersion, LifecycleAdmission, NodeIdentityState, NodeResidue, RouteGateState,
    SessionBinding, Sha256Digest, WireU64,
};
use cats_storage::authority::AuthorityError;
use postgres::Transaction;

use super::route_signing_authority::load_current_signer;
use super::rows::database_now;
use super::runtime_spine::{
    load_admission_inventory_state_unlocked, load_placement_admission_at_in_checked,
    PlacementAdmissionLoad, PLACEMENT_INVENTORY_MAX_AGE_MS,
};
use crate::store::agent_sessions::{
    load_current_session_unlocked, load_identity_history_after_for_fleet_verification,
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
            fleet_verification_snapshot_in(
                transaction,
                approved_guest_config_digest,
                request,
                &mut |_| {},
            )
        })
    }
}

fn fleet_verification_snapshot_in(
    transaction: &mut Transaction<'_>,
    approved_guest_config_digest: &Sha256Digest,
    request: &AuthorityRequestContext,
    page_observer: &mut impl FnMut(usize),
) -> AuthorityTxResult<FleetVerificationSnapshot> {
    request.refresh_transaction_deadline(transaction)?;
    let validation_at_unix_ms = database_now(transaction)?;
    validate_child_node_ownership(transaction, ChildNodeTable::CurrentSessions)?;
    request.refresh_transaction_deadline(transaction)?;
    validate_child_node_ownership(transaction, ChildNodeTable::AdmissionInventories)?;

    let mut nodes = Vec::new();
    let mut after = None;
    let mut page_number = 0_usize;
    loop {
        // A fleet has no Node-count cap. Each bounded keyset page gets a
        // fresh cancellation checkpoint and the remaining absolute deadline;
        // all pages still belong to this one repeatable-read snapshot.
        request.refresh_transaction_deadline(transaction)?;
        let identities =
            load_identity_history_after_for_fleet_verification(transaction, after.as_ref())?;
        let Some(last) = identities
            .last()
            .map(|(identity, _, _)| identity.node_id.clone())
        else {
            break;
        };
        for (identity, has_session, has_inventory) in identities {
            if identity.state == NodeIdentityState::Retired {
                continue;
            }
            if identity.state != NodeIdentityState::Provisioned {
                return Err(corrupt("NodeIdentity has an unknown state"));
            }

            // Reuse the complete A20 admission loader at the fleet's single
            // DB clock. Ordinary absence/expiry remains observable as
            // not-ready facts; internal binding, causality, projection and
            // future-time failures remain fatal Store corruption.
            let (session, inventory) = if has_session || has_inventory {
                let admission = load_placement_admission_at_in_checked(
                    transaction,
                    &identity.node_id,
                    approved_guest_config_digest,
                    validation_at_unix_ms,
                    &mut |transaction| request.refresh_transaction_deadline(transaction),
                )?;
                match admission {
                    PlacementAdmissionLoad::Accepted(admission) => {
                        let inventory = summarize_inventory(
                            &admission.inventory_attestation,
                            &admission.full_inventory_observation,
                            admission.assigned_desired_specs.len(),
                        )?;
                        (Some(admission.agent_session), Some(inventory))
                    }
                    PlacementAdmissionLoad::Rejected(_) => {
                        request.refresh_transaction_deadline(transaction)?;
                        let session =
                            load_current_session_unlocked(transaction, &identity.node_id)?;
                        request.refresh_transaction_deadline(transaction)?;
                        let inventory = load_admission_inventory_state_unlocked(
                            transaction,
                            &identity.node_id,
                        )?
                        .map(|state| {
                            if state.attestation.accepted_at_unix_ms > validation_at_unix_ms {
                                return Err(corrupt(
                                    "database time moved behind admission inventory acceptance",
                                ));
                            }
                            summarize_inventory(
                                &state.attestation,
                                &state.full_observation,
                                state.assigned_snapshot.desired_specs.len(),
                            )
                        })
                        .transpose()?;
                        (session, inventory)
                    }
                }
            } else {
                (None, None)
            };
            nodes.push(FleetVerificationNode {
                node_id: identity.node_id,
                session,
                inventory,
            });
        }
        page_number = page_number
            .checked_add(1)
            .ok_or_else(|| corrupt("fleet verification page counter overflow"))?;
        page_observer(page_number);
        after = Some(last);
    }

    request.refresh_transaction_deadline(transaction)?;
    let desired_runtime_count: i64 = transaction
        .query_one("SELECT count(*) FROM desired_runtime_specs", &[])?
        .try_get(0)?;
    let desired_runtime_count = u64::try_from(desired_runtime_count)
        .ok()
        .and_then(WireU64::new)
        .ok_or_else(|| corrupt("desired runtime count is outside the wire range"))?;
    request.refresh_transaction_deadline(transaction)?;
    let current_runtime_observation_count: i64 = transaction
        .query_one("SELECT count(*) FROM runtime_current_cat_observations", &[])?
        .try_get(0)?;
    let current_runtime_observation_count = u64::try_from(current_runtime_observation_count)
        .ok()
        .and_then(WireU64::new)
        .ok_or_else(|| corrupt("current runtime observation count is outside the wire range"))?;

    request.refresh_transaction_deadline(transaction)?;
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
    // Report the conservative clock after the complete facts load, while the
    // A20 validator above used one earlier DB clock for every Node. If the
    // server clock moved backward during this snapshot, or a stored server
    // acceptance is still in its future, the Store is corrupt rather than an
    // ordinary not-ready fleet.
    request.refresh_transaction_deadline(transaction)?;
    let evaluated_at_unix_ms = database_now(transaction)?;
    if evaluated_at_unix_ms < validation_at_unix_ms {
        return Err(corrupt(
            "database time moved backward during fleet verification",
        ));
    }
    for inventory in nodes.iter().filter_map(|node| node.inventory.as_ref()) {
        if inventory.attestation.accepted_at_unix_ms > evaluated_at_unix_ms
            || inventory
                .attestation
                .accepted_at_unix_ms
                .get()
                .checked_add(PLACEMENT_INVENTORY_MAX_AGE_MS)
                .is_none()
        {
            return Err(corrupt(
                "fleet inventory acceptance is outside the database clock range",
            ));
        }
    }
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

fn validate_child_node_ownership(
    transaction: &mut Transaction<'_>,
    table: ChildNodeTable,
) -> AuthorityTxResult<()> {
    let sql = match table {
        ChildNodeTable::CurrentSessions => {
            "SELECT child.node_id
               FROM current_agent_sessions AS child
               LEFT JOIN node_identities AS identity USING (node_id)
              WHERE identity.node_id IS NULL OR identity.state <> 'provisioned'
              ORDER BY child.node_id COLLATE \"C\"
              LIMIT 1"
        }
        ChildNodeTable::AdmissionInventories => {
            "SELECT child.node_id
               FROM runtime_admission_inventory_states AS child
               LEFT JOIN node_identities AS identity USING (node_id)
              WHERE identity.node_id IS NULL OR identity.state <> 'provisioned'
              ORDER BY child.node_id COLLATE \"C\"
              LIMIT 1"
        }
    };
    if transaction.query_opt(sql, &[])?.is_some() {
        return Err(corrupt(
            "current session/inventory row does not belong to a provisioned identity",
        ));
    }
    Ok(())
}

fn summarize_inventory(
    attestation: &cats_api::runtime_reconciliation::AdmissionInventoryAttestation,
    observation: &cats_api::runtime_reconciliation::NodeObservation,
    assigned_desired_count: usize,
) -> AuthorityTxResult<FleetVerificationInventory> {
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
        attestation: attestation.clone(),
        source_observation_id: observation.observation_id.clone(),
        source_heartbeat_sequence: observation.heartbeat_sequence,
        source_observed_at_unix_ms: observation.observed_at_unix_ms,
        complete_inventory: observation.complete_inventory,
        assigned_desired_count: wire_count(assigned_desired_count)?,
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
    use crate::store::agent_sessions::{insert_node_identity_in, retire_node_identity_in};

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn identity(suffix: &str, digest_byte: u8) -> NodeIdentity {
        NodeIdentity {
            version: ContractVersion::V1,
            node_id: id(&format!("node_{suffix}")),
            provider_scope: cats_api::runtime_reconciliation::ProviderScope {
                provider: id("test_provider"),
                partition: id("test_partition"),
                account_id: id("test_account"),
                region: id("test_region"),
            },
            immutable_host_id: id(&format!("host_{suffix}")),
            credential_id: id(&format!("credential_{suffix}")),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: Sha256Digest::from_bytes([digest_byte; 32]),
            },
            state_path_id: id(&format!("state_{suffix}")),
            state: NodeIdentityState::Provisioned,
        }
    }

    fn indexed_identity(kind: &str, index: usize) -> NodeIdentity {
        let mut digest = [0_u8; 32];
        let (digest_kind, node_kind) = match kind {
            "active" => (1, "active"),
            // Sort retired history ahead of the current fleet so the
            // regression proves pagination reaches every provisioned row.
            "retired" => (2, "000_retired"),
            _ => unreachable!("test identity kind is closed"),
        };
        digest[0] = digest_kind;
        digest[1..9].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
        NodeIdentity {
            version: ContractVersion::V1,
            node_id: id(&format!("node_{node_kind}_{index:04}")),
            provider_scope: cats_api::runtime_reconciliation::ProviderScope {
                provider: id("test_provider"),
                partition: id("test_partition"),
                account_id: id("test_account"),
                region: id("test_region"),
            },
            immutable_host_id: id(&format!("host_{kind}_{index:04}")),
            credential_id: id(&format!("credential_{kind}_{index:04}")),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: Sha256Digest::from_bytes(digest),
            },
            state_path_id: id(&format!("state_{kind}_{index:04}")),
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
                    let first =
                        load_identity_history_after_for_fleet_verification(transaction, None)?;
                    assert_eq!(first.len(), 1);
                    entered_send.send(()).unwrap();
                    continue_receive.recv().unwrap();
                    let request = request();
                    let snapshot = fleet_verification_snapshot_in(
                        transaction,
                        &approved,
                        &request,
                        &mut |_| {},
                    )?;
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

    #[test]
    fn fleet_snapshot_pages_more_than_1024_active_nodes_and_ignores_retired_cardinality() {
        const ACTIVE: usize = 1_025;
        const RETIRED: usize = 1_500;

        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        store
            .authority_transaction(|transaction| {
                let committed_at = database_now(transaction)?;
                for index in 0..ACTIVE {
                    let identity = indexed_identity("active", index);
                    if insert_node_identity_in(transaction, &identity, committed_at)? != 1 {
                        return Err(corrupt("active fleet identity was not inserted"));
                    }
                }
                for index in 0..RETIRED {
                    let identity = indexed_identity("retired", index);
                    if insert_node_identity_in(transaction, &identity, committed_at)? != 1 {
                        return Err(corrupt("retired fleet identity was not inserted"));
                    }
                    retire_node_identity_in(transaction, &identity, committed_at)?;
                }
                Ok(())
            })
            .unwrap();

        let snapshot = store
            .fleet_verification_snapshot(&request(), &Sha256Digest::from_bytes([9; 32]))
            .unwrap();
        assert_eq!(snapshot.nodes.len(), ACTIVE);
        assert_eq!(
            snapshot.nodes.first().unwrap().node_id,
            id("node_active_0000")
        );
        assert_eq!(
            snapshot.nodes.last().unwrap().node_id,
            id("node_active_1024")
        );
        assert!(snapshot
            .nodes
            .iter()
            .all(|node| node.session.is_none() && node.inventory.is_none()));
    }

    #[test]
    fn fleet_snapshot_treats_identity_session_host_drift_as_fatal_corruption() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let release = crate::testsupport::test_guest_runtime_profile_receipt();
        let admission = super::super::runtime_spine_tests::establish_empty_admission_for(
            &store,
            &release,
            "host_drift",
            11,
        );
        store
            .with(|client| {
                client.batch_execute(
                    "DROP TRIGGER node_identity_lineage_is_immutable ON node_identities;
                     UPDATE node_identities
                        SET immutable_host_id='host_coherently_corrupt',
                            record=jsonb_set(
                                record,
                                '{immutable_host_id}',
                                to_jsonb('host_coherently_corrupt'::TEXT)
                            )
                      WHERE node_id='node_host_drift';",
                )
            })
            .unwrap();

        let error = store
            .fleet_verification_snapshot(&request(), &admission.agent_session.guest_config_digest)
            .unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Internal);
    }

    #[test]
    fn fleet_snapshot_treats_future_acceptance_or_clock_rollback_as_fatal_corruption() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let release = crate::testsupport::test_guest_runtime_profile_receipt();
        let admission = super::super::runtime_spine_tests::establish_empty_admission_for(
            &store, &release, "future", 12,
        );
        store
            .with(|client| {
                client.execute(
                    "UPDATE current_agent_sessions
                        SET lease_deadline_unix_ms=1,
                            record=jsonb_set(
                                record,
                                '{lease_deadline_unix_ms}',
                                to_jsonb(1::BIGINT)
                            )
                      WHERE node_id=$1",
                    &[&admission.node_identity.node_id.as_str()],
                )?;
                client.execute(
                    "UPDATE runtime_admission_inventory_states
                        SET accepted_at_unix_ms=accepted_at_unix_ms + 20000,
                            attestation=jsonb_set(
                                attestation,
                                '{accepted_at_unix_ms}',
                                to_jsonb(accepted_at_unix_ms + 20000)
                            )
                      WHERE node_id=$1",
                    &[&admission.node_identity.node_id.as_str()],
                )
            })
            .unwrap();

        let error = store
            .fleet_verification_snapshot(&request(), &admission.agent_session.guest_config_digest)
            .unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Internal);
    }

    #[test]
    fn cancelled_page_scan_rolls_back_and_reuses_the_connection_without_a_late_result() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        store
            .authority_transaction(|transaction| {
                let committed_at = database_now(transaction)?;
                for index in 0..65 {
                    let identity = indexed_identity("active", index);
                    insert_node_identity_in(transaction, &identity, committed_at)?;
                }
                Ok(())
            })
            .unwrap();
        let request = request();
        let request_for_page = request.clone();
        let error = store
            .authority_request_read_snapshot(&request, |transaction| {
                fleet_verification_snapshot_in(
                    transaction,
                    &Sha256Digest::from_bytes([9; 32]),
                    &request_for_page,
                    &mut |page| {
                        if page == 1 {
                            request_for_page.cancel();
                        }
                    },
                )
            })
            .unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);
        assert_eq!(
            store
                .with(|client| client
                    .query_one("SELECT 1", &[])
                    .map(|row| row.get::<_, i32>(0)))
                .unwrap(),
            1
        );
    }

    #[test]
    fn page_scan_recomputes_the_remaining_deadline_and_rejects_a_late_snapshot() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        store
            .authority_transaction(|transaction| {
                let committed_at = database_now(transaction)?;
                for index in 0..65 {
                    let identity = indexed_identity("active", index);
                    insert_node_identity_in(transaction, &identity, committed_at)?;
                }
                Ok(())
            })
            .unwrap();
        let request = AuthorityRequestContext::new(Instant::now() + Duration::from_millis(500));
        let request_for_page = request.clone();
        let mut crossed_deadline = false;
        let error = store
            .authority_request_read_snapshot(&request, |transaction| {
                fleet_verification_snapshot_in(
                    transaction,
                    &Sha256Digest::from_bytes([9; 32]),
                    &request_for_page,
                    &mut |page| {
                        if page == 1 {
                            std::thread::sleep(Duration::from_millis(550));
                            crossed_deadline = true;
                        }
                    },
                )
            })
            .unwrap_err();
        assert!(crossed_deadline, "test did not cross a page boundary");
        assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);
        assert_eq!(
            store
                .with(|client| client
                    .query_one("SELECT 1", &[])
                    .map(|row| row.get::<_, i32>(0)))
                .unwrap(),
            1
        );
    }
}
