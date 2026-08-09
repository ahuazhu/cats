use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    guest_config_digest, AgentRegistrationAttempt, AgentSession, AsciiText as RuntimeAsciiText,
    ContractVersion, CredentialBinding, GuestRuntimeProfileReceipt, NodeBootId, NodeIdentity,
    NodeIdentityState, RuntimeVolumeTransitionEvidenceRequest, SessionBinding,
};
use cats_storage::authority::{
    complete_disposable_root_delete, consume_disposable_root_delete, AsciiText,
    AuthorizationRecord, AuthorizationState, DeleteCompletionReceipt,
    DisposableDeleteIsolationBasis, DisposableRootDeleteAuthorization, Epoch, FenceEpoch,
    Generation, HostFenceEvent, HostFenceEventState, HostIsolationState, Id, NormalAcquireRequest,
    RandomId128, ReleaseRequest, RemoteHead, Revision, Sha256Digest, UnixMillis, VolumeAdminState,
    VolumeAuthorization, VolumeDurability, VolumeRecord, VolumeTakeoverAuthorization,
};

use super::rows::{
    database_now, insert_authorization, insert_delete_completion, insert_event, insert_volume,
    load_active_event_by_node_unlocked, load_authorization_for_update,
    load_delete_completion_for_update, load_event_for_update, load_volume_for_update,
    update_authorization, update_event, update_volume,
};
use super::volume_transition_auth::{
    authenticate_evidence_context_in, VolumeTransitionStoreOutcome, VolumeTransitionStoreRejection,
};
use super::volume_transition_evidence::{
    load_volume_transition_evidence_in, VolumeTransitionEvidenceLoad,
};
use crate::store::agent_sessions::{
    load_identity_by_node_for_update, rotate_public_key_identity_in, AgentRegistrationOutcome,
    AgentSessionRegistrationPolicy, AuthenticatedNodeCredential,
};
use crate::store::transaction::{authority_transaction_attempts, AuthorityTransactionError};
use crate::store::{metrics_snapshot, Store};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random_id(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn revision(value: u64) -> Revision {
    Revision::new(value).unwrap()
}

fn epoch(value: u64) -> Epoch {
    Epoch::new(value).unwrap()
}

fn fence_epoch(value: u64) -> FenceEpoch {
    FenceEpoch::new(value).unwrap()
}

fn generation(value: u64) -> Generation {
    Generation::new(value).unwrap()
}

fn unix_millis(value: u64) -> UnixMillis {
    UnixMillis::new(value).unwrap()
}

fn boot_id(value: u128) -> NodeBootId {
    NodeBootId::new(format!("{value:032x}")).unwrap()
}

fn runtime_release() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: Sha256Digest::from_bytes([1; 32]),
        initramfs_digest: Some(Sha256Digest::from_bytes([2; 32])),
        kernel_cmdline: RuntimeAsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

#[derive(Clone)]
struct TransitionNode {
    authenticated: AuthenticatedNodeCredential,
    session: SessionBinding,
    active_guest_config_digest: Sha256Digest,
}

fn transition_node(store: &Store, node_id: &str) -> TransitionNode {
    let suffix = if node_id == "node-new" { 9 } else { 10 };
    let identity = NodeIdentity {
        version: ContractVersion::V1,
        node_id: id(node_id),
        immutable_host_id: id(&format!("host-{suffix}")),
        credential_id: id(&format!("credential-{suffix}")),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::from_bytes([suffix; 32]),
        },
        state_path_id: id(&format!("state-path-{suffix}")),
        state: NodeIdentityState::Provisioned,
    };
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    let release = runtime_release();
    let policy =
        AgentSessionRegistrationPolicy::from_release_receipt(&release, Duration::from_secs(120))
            .unwrap();
    store.provision_node_identity(&identity).unwrap();
    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id,
        immutable_host_id: identity.immutable_host_id,
        node_boot_id: boot_id(41),
        agent_instance_id: random_id(42),
        registration_attempt_id: random_id(43),
        guest_config_digest: policy.approved_guest_config_digest().clone(),
        expected_agent_session_epoch: None,
    };
    let session = match store
        .register_agent_session(&authenticated, &attempt, &policy)
        .unwrap()
    {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => {
            panic!("transition AgentSession was rejected: {rejection:?}")
        }
    };
    TransitionNode {
        authenticated,
        session: session_binding(&session),
        active_guest_config_digest: guest_config_digest(&release).unwrap(),
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

fn evidence_request(node_id: &str) -> RuntimeVolumeTransitionEvidenceRequest {
    evidence_request_for(node_id, "takeover-auth-1")
}

fn evidence_request_for(
    node_id: &str,
    authorization_id: &str,
) -> RuntimeVolumeTransitionEvidenceRequest {
    RuntimeVolumeTransitionEvidenceRequest {
        version: ContractVersion::V1,
        session: SessionBinding {
            node_id: id(node_id),
            node_boot_id: boot_id(41),
            agent_instance_id: random_id(42),
            agent_session_epoch: epoch(1),
        },
        authorization_id: id(authorization_id),
    }
}

fn head(value: u64) -> RemoteHead {
    RemoteHead {
        generation: generation(value),
        root_hash: (value > 0).then(|| Sha256Digest::new(format!("sha256:{value:064x}")).unwrap()),
        root_object_id: (value > 0).then(|| AsciiText::new(format!("roots/{value}")).unwrap()),
    }
}

fn unowned_volume() -> VolumeRecord {
    VolumeRecord {
        volume_id: id("volume-1"),
        size_bytes: 4 * 1024 * 1024,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        head: head(4),
        lease_owner: None,
        lease_epoch: fence_epoch(7),
        lease_expires_at: None,
        last_transition: None,
    }
}

fn acquire_request(
    transition: u128,
    attachment: &str,
    expected_epoch: u64,
) -> NormalAcquireRequest {
    NormalAcquireRequest {
        volume_id: id("volume-1"),
        transition_id: random_id(transition),
        attachment_id: id(attachment),
        expected_unowned_epoch: fence_epoch(expected_epoch),
        desired_revision: revision(11),
        placement_epoch: epoch(3),
        lease_duration_ms: 30_000,
    }
}

fn host_fence_event(state: HostFenceEventState) -> HostFenceEvent {
    HostFenceEvent {
        event_id: id("fence-event-1"),
        provider: id("provider-1"),
        immutable_host_id: id("host-1"),
        node_id: id("node-old"),
        expected_node_boot_id: cats_storage::authority::NodeBootId::new(format!("{:032x}", 1))
            .unwrap(),
        expected_agent_session_epoch: epoch(8),
        fence_attempt_id: id("fence-attempt-1"),
        isolation_state: HostIsolationState::Isolated,
        observed_at: unix_millis(12_000),
        state,
    }
}

fn takeover_authorization(volume: &VolumeRecord) -> AuthorizationRecord {
    AuthorizationRecord {
        authorization: VolumeAuthorization::Takeover(VolumeTakeoverAuthorization {
            authorization_id: id("takeover-auth-1"),
            authorized_node_id: id("node-new"),
            host_fence_event_id: id("fence-event-1"),
            volume_id: volume.volume_id.clone(),
            expected_attachment_id: volume.lease_owner.clone().unwrap(),
            expected_epoch: volume.lease_epoch,
            new_attachment_id: id("attachment-new"),
            desired_revision: revision(12),
            new_placement_epoch: epoch(4),
            lease_duration_ms: 30_000,
            not_after: unix_millis(i64::MAX.unsigned_abs()),
        }),
        state: AuthorizationState::Unconsumed,
    }
}

fn disposable_authorization(volume: &VolumeRecord) -> AuthorizationRecord {
    AuthorizationRecord {
        authorization: VolumeAuthorization::DisposableRootDelete(
            DisposableRootDeleteAuthorization {
                authorization_id: id("delete-auth-1"),
                authorized_node_id: id("node-new"),
                delete_id: id("delete-1"),
                disk_id: id("disk-1"),
                volume_id: volume.volume_id.clone(),
                cat_id: id("cat-1"),
                desired_revision: revision(12),
                placement_epoch: epoch(4),
                expected_attachment_id: volume.lease_owner.clone().unwrap(),
                expected_epoch: volume.lease_epoch,
                expected_head: volume.head.clone(),
                isolation_basis: DisposableDeleteIsolationBasis::RuntimeStopped {
                    node_id: id("node-new"),
                    agent_session_epoch: epoch(3),
                    runtime_incarnation: random_id(51),
                    observation_id: random_id(52),
                },
                not_after: unix_millis(50_000),
            },
        ),
        state: AuthorizationState::Unconsumed,
    }
}

fn store_pair() -> (String, Store, Store) {
    let url = crate::testsupport::isolated_control_store_url();
    let first = Store::connect(&url, None).unwrap();
    let second = Store::connect(&url, None).unwrap();
    (url, first, second)
}

fn seed_volume(store: &Store, record: &VolumeRecord) {
    store
        .authority_transaction(|transaction| insert_volume(transaction, record))
        .unwrap();
}

fn seed_takeover(store: &Store, event: &HostFenceEvent, authorization: &AuthorizationRecord) {
    store
        .authority_transaction(|transaction| {
            insert_event(transaction, event)?;
            insert_authorization(transaction, authorization)
        })
        .unwrap();
}

fn stored_volume(store: &Store, volume_id: &Id) -> VolumeRecord {
    store
        .authority_transaction(|transaction| {
            Ok(load_volume_for_update(transaction, volume_id)?.unwrap())
        })
        .unwrap()
}

fn stored_authorization(store: &Store, authorization_id: &Id) -> AuthorizationRecord {
    store
        .authority_transaction(|transaction| {
            Ok(load_authorization_for_update(transaction, authorization_id)?.unwrap())
        })
        .unwrap()
}

fn stored_event(store: &Store, event_id: &Id) -> HostFenceEvent {
    store
        .authority_transaction(|transaction| {
            Ok(load_event_for_update(transaction, event_id)?.unwrap())
        })
        .unwrap()
}

#[test]
fn canonical_active_fence_cannot_be_hidden_by_projection_drift() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let event = host_fence_event(HostFenceEventState::Active);
    store
        .authority_transaction(|transaction| insert_event(transaction, &event))
        .unwrap();
    store
        .with(|client| {
            client.execute(
                "UPDATE host_fence_events SET state='rejoined' WHERE event_id=$1",
                &[&event.event_id.as_str()],
            )
        })
        .unwrap();

    let error = store
        .authority_transaction(|transaction| {
            load_active_event_by_node_unlocked(transaction, &event.node_id)
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

fn stored_authorization_row(store: &Store, authorization_id: &Id) -> String {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT to_jsonb(volume_authorizations)::text
                       FROM volume_authorizations
                      WHERE authorization_id=$1",
                    &[&authorization_id.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap()
}

fn acquire_owned_volume(store: &Store) -> VolumeRecord {
    seed_volume(store, &unowned_volume());
    store
        .acquire_volume_authority(&acquire_request(1, "attachment-old", 7))
        .unwrap();
    stored_volume(store, &id("volume-1"))
}

fn consume_takeover_as(
    store: &Store,
    authorization_id: &Id,
    authorized_node_id: &Id,
) -> crate::store::Result<cats_storage::authority::TakeoverResult> {
    let node = transition_node(store, authorized_node_id.as_str());
    consume_takeover_with_node(store, authorization_id, &node)
}

fn consume_takeover_with_node(
    store: &Store,
    authorization_id: &Id,
    node: &TransitionNode,
) -> crate::store::Result<cats_storage::authority::TakeoverResult> {
    match store.runtime_consume_volume_takeover(
        &node.authenticated,
        &node.session,
        authorization_id,
        &node.active_guest_config_digest,
    )? {
        VolumeTransitionStoreOutcome::Accepted(result) => Ok(result),
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            panic!("authenticated takeover was rejected before authority: {rejection:?}")
        }
    }
}

fn load_evidence(
    transaction: &mut postgres::Transaction<'_>,
    node: &TransitionNode,
    request: &RuntimeVolumeTransitionEvidenceRequest,
) -> Result<VolumeTransitionEvidenceLoad, AuthorityTransactionError> {
    let context = match authenticate_evidence_context_in(
        transaction,
        &node.authenticated,
        &request.session,
        &node.active_guest_config_digest,
    )? {
        VolumeTransitionStoreOutcome::Accepted(context) => context,
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            panic!("evidence authentication prefix was rejected: {rejection:?}")
        }
    };
    load_volume_transition_evidence_in(context, request)
}

fn load_evidence_public(
    store: &Store,
    node: &TransitionNode,
    request: &RuntimeVolumeTransitionEvidenceRequest,
) -> crate::store::Result<VolumeTransitionEvidenceLoad> {
    match store.runtime_volume_transition_evidence(
        &node.authenticated,
        request,
        &node.active_guest_config_digest,
    )? {
        VolumeTransitionStoreOutcome::Accepted(load) => Ok(load),
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            panic!("evidence Store entrypoint was rejected: {rejection:?}")
        }
    }
}

#[test]
fn persisted_volume_replays_lost_result_and_rejects_reused_id() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    seed_volume(&store, &unowned_volume());
    let request = acquire_request(1, "attachment-old", 7);

    // Simulate a commit response that the caller lost by discarding it.
    let first = store.acquire_volume_authority(&request).unwrap();
    let replay = store.acquire_volume_authority(&request).unwrap();
    assert_eq!(replay, first);

    let before = stored_volume(&store, &request.volume_id);
    let changed = NormalAcquireRequest {
        attachment_id: id("attachment-other"),
        ..request
    };
    let error = store.acquire_volume_authority(&changed).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(stored_volume(&store, &changed.volume_id), before);
}

#[test]
fn malformed_json_and_projection_mismatch_fail_closed() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let volume = unowned_volume();
    seed_volume(&store, &volume);
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_records SET size_bytes=size_bytes+1 WHERE volume_id=$1",
                    &[&volume.volume_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = store
        .acquire_volume_authority(&acquire_request(1, "attachment-old", 7))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_records
                        SET size_bytes=$2,
                            record=record || '{\"unexpected\":true}'::jsonb
                      WHERE volume_id=$1",
                    &[
                        &volume.volume_id.as_str(),
                        &i64::try_from(volume.size_bytes).unwrap(),
                    ],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = store
        .acquire_volume_authority(&acquire_request(2, "attachment-old", 7))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn expired_foreign_owner_stays_owned_but_exact_owner_can_renew() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_records
                        SET lease_expires_at=1,
                            record=jsonb_set(record, '{lease_expires_at}', '1'::jsonb)
                      WHERE volume_id=$1",
                    &[&owned.volume_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();

    let error = store
        .acquire_volume_authority(&acquire_request(2, "attachment-new", 8))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);

    let renewed = store
        .renew_volume_authority(&cats_storage::authority::RenewLeaseRequest {
            volume_id: owned.volume_id.clone(),
            attachment_id: id("attachment-old"),
            expected_epoch: fence_epoch(8),
            lease_duration_ms: 30_000,
        })
        .unwrap();
    assert_eq!(renewed.epoch, fence_epoch(8));
    assert!(renewed.lease_expires_at.get() > 1);
}

#[test]
fn release_reacquire_fences_a_late_release() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let old_release = ReleaseRequest {
        volume_id: owned.volume_id.clone(),
        transition_id: random_id(2),
        attachment_id: id("attachment-old"),
        expected_epoch: fence_epoch(8),
    };
    let released = store.release_volume_authority(&old_release).unwrap();
    assert_eq!(released.resulting_epoch, fence_epoch(9));
    store
        .acquire_volume_authority(&acquire_request(3, "attachment-new", 9))
        .unwrap();
    let before = stored_volume(&store, &owned.volume_id);

    let error = store.release_volume_authority(&old_release).unwrap_err();
    assert_eq!(error.code, ErrorCode::StaleEpoch);
    assert_eq!(stored_volume(&store, &owned.volume_id), before);
}

#[test]
fn two_store_sessions_cannot_both_acquire_one_volume() {
    let (_url, first, second) = store_pair();
    seed_volume(&first, &unowned_volume());
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let first_worker = std::thread::spawn(move || {
        first_barrier.wait();
        first.acquire_volume_authority(&acquire_request(1, "attachment-a", 7))
    });
    let second_worker = std::thread::spawn(move || {
        second_barrier.wait();
        second.acquire_volume_authority(&acquire_request(2, "attachment-b", 7))
    });
    barrier.wait();
    let outcomes = [first_worker.join().unwrap(), second_worker.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter_map(|result| result.as_ref().err())
            .filter(|error| error.code == ErrorCode::Conflict)
            .count(),
        1
    );
}

#[test]
fn takeover_wrong_tuple_has_zero_side_effect_and_consumed_row_replays() {
    let (url, store, observer) = store_pair();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let mut wrong = takeover_authorization(&owned);
    let VolumeAuthorization::Takeover(payload) = &mut wrong.authorization else {
        unreachable!()
    };
    payload.expected_attachment_id = id("wrong-attachment");
    seed_takeover(&store, &event, &wrong);
    let before_volume = stored_volume(&store, &owned.volume_id);
    let before_authorization = stored_authorization(&store, &id("takeover-auth-1"));
    let error = consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap_err();
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(stored_volume(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization(&store, &id("takeover-auth-1")),
        before_authorization
    );

    // Replace only the rejected fixture, then prove that a committed receipt
    // is the replay authority even if the Volume row no longer exists.
    store
        .with(|client| {
            client
                .execute(
                    "DELETE FROM volume_authorizations WHERE authorization_id=$1",
                    &[&"takeover-auth-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    let valid = takeover_authorization(&before_volume);
    store
        .authority_transaction(|transaction| insert_authorization(transaction, &valid))
        .unwrap();
    let first = consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap();
    observer
        .with(|client| {
            client
                .execute(
                    "DELETE FROM volume_records WHERE volume_id=$1",
                    &[&"volume-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    drop(Store::connect(&url, None).unwrap());
    assert_eq!(
        consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap(),
        first
    );
}

#[test]
fn evidence_snapshot_returns_the_exact_consumed_takeover_bundle() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap();

    let node = transition_node(&store, "node-new");
    let request = evidence_request("node-new");
    let loaded = store
        .authority_locking_read_snapshot(|transaction| {
            let isolation: String = transaction
                .query_one("SHOW transaction_isolation", &[])?
                .get(0);
            let read_only: String = transaction
                .query_one("SHOW transaction_read_only", &[])?
                .get(0);
            assert_eq!(isolation, "repeatable read");
            assert_eq!(read_only, "off");
            load_evidence(transaction, &node, &request)
        })
        .unwrap();
    let VolumeTransitionEvidenceLoad::Available(success) = loaded else {
        panic!("authorized evidence unexpectedly unavailable")
    };
    assert_eq!(success.authorization_id, request.authorization_id);
    assert_eq!(success.session, request.session);
    assert_eq!(
        success.authorization,
        stored_authorization(&store, &id("takeover-auth-1"))
    );
    assert_eq!(
        success.current_volume,
        Some(stored_volume(&store, &owned.volume_id))
    );
    assert_eq!(success.delete_completion, None);
    assert_eq!(success.direct_successor_authorization, None);
}

#[test]
fn evidence_snapshot_rejects_a_future_consumption_timestamp() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap();
    let node = transition_node(&store, "node-new");

    let db_now = store.authority_locking_read_snapshot(database_now).unwrap();
    let future = unix_millis(db_now.get() + 60_000);
    let future_not_after = unix_millis(db_now.get() + 180_000);
    let mut corrupted = stored_authorization(&store, &id("takeover-auth-1"));
    let VolumeAuthorization::Takeover(authorization) = &mut corrupted.authorization else {
        unreachable!()
    };
    authorization.not_after = future_not_after;
    let AuthorizationState::Consumed(receipt) = &mut corrupted.state else {
        unreachable!()
    };
    let cats_storage::authority::AuthorizationConsumedReceipt::Takeover(receipt) = receipt.as_mut()
    else {
        unreachable!()
    };
    receipt.consumed_at = future;
    let record_json = serde_json::to_string(&corrupted).unwrap();
    let future = i64::try_from(future.get()).unwrap();
    let future_not_after = i64::try_from(future_not_after.get()).unwrap();
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_authorizations
                        SET record=$2::TEXT::jsonb, consumed_at=$3, not_after=$4
                      WHERE authorization_id=$1",
                    &[&"takeover-auth-1", &record_json, &future, &future_not_after],
                )
                .map(|_| ())
        })
        .unwrap();

    let request = evidence_request("node-new");
    let error = store
        .authority_locking_read_snapshot(|transaction| load_evidence(transaction, &node, &request))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn evidence_access_predicate_hides_wrong_node_before_protected_decode() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let wrong_node = transition_node(&store, "node-other");

    // Calibrate the query with the known authorized Node before corrupting the
    // protected payload. This makes the negative isolation assertion prove
    // the access predicate rather than a typo in the fixture.
    let request = evidence_request("node-new");
    assert!(matches!(
        load_evidence_public(&store, &node, &request).unwrap(),
        VolumeTransitionEvidenceLoad::Available(_)
    ));
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_authorizations
                        SET record=record || '{\"unexpected\":true}'::jsonb
                      WHERE authorization_id=$1",
                    &[&"takeover-auth-1"],
                )
                .map(|_| ())
        })
        .unwrap();

    let wrong_request = evidence_request("node-other");
    let wrong = load_evidence_public(&store, &wrong_node, &wrong_request).unwrap();
    assert_eq!(
        wrong,
        VolumeTransitionEvidenceLoad::Unavailable {
            authorization_id: id("takeover-auth-1")
        }
    );
    let error = load_evidence_public(&store, &node, &request).unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn evidence_rejects_wrong_credential_lineage_before_protected_rows() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let request = evidence_request("node-new");

    // First calibrate the public Store entrypoint with the exact active
    // lineage. Then corrupt the protected row: a wrong proof binding must
    // still stop at identity admission and never expose that corruption.
    assert!(matches!(
        load_evidence_public(&store, &node, &request).unwrap(),
        VolumeTransitionEvidenceLoad::Available(_)
    ));
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_authorizations
                        SET record=record || '{\"unexpected\":true}'::jsonb
                      WHERE authorization_id=$1",
                    &[&"takeover-auth-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    let wrong = AuthenticatedNodeCredential::new(
        node.authenticated.credential_id().clone(),
        CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::from_bytes([77; 32]),
        },
    );
    let outcome = store
        .runtime_volume_transition_evidence(&wrong, &request, &node.active_guest_config_digest)
        .unwrap();
    assert_eq!(
        outcome,
        VolumeTransitionStoreOutcome::Rejected(VolumeTransitionStoreRejection::IdentityNotEligible)
    );
}

#[test]
fn evidence_share_locks_hold_credential_rotation_until_snapshot_commit() {
    let (_url, seed, reader) = store_pair();
    let owned = acquire_owned_volume(&seed);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&seed, &event, &authorization);
    let node = transition_node(&seed, "node-new");
    let request = evidence_request("node-new");

    let reader_node = node.clone();
    let reader_request = request.clone();
    let (prefix_tx, prefix_rx) = mpsc::channel();
    let (finish_read_tx, finish_read_rx) = mpsc::channel();
    let reader_worker = std::thread::spawn(move || {
        reader.authority_locking_read_snapshot(move |transaction| {
            let context = match authenticate_evidence_context_in(
                transaction,
                &reader_node.authenticated,
                &reader_request.session,
                &reader_node.active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => context,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    panic!("evidence prefix rejected: {rejection:?}")
                }
            };
            prefix_tx.send(()).unwrap();
            finish_read_rx.recv().unwrap();
            load_volume_transition_evidence_in(context, &reader_request)
        })
    });
    prefix_rx.recv().unwrap();

    let rotator = Store::connect_from(&seed.dsn, None).unwrap();
    let (rotation_started_tx, rotation_started_rx) = mpsc::channel();
    let (rotation_finished_tx, rotation_finished_rx) = mpsc::channel();
    let rotation_worker = std::thread::spawn(move || {
        let outcome = rotator.authority_transaction(|transaction| {
            rotation_started_tx.send(()).unwrap();
            let current = load_identity_by_node_for_update(transaction, &id("node-new"))?
                .expect("transition NodeIdentity exists");
            let committed_at = database_now(transaction)?;
            rotate_public_key_identity_in(
                transaction,
                &current,
                &id("credential-rotated"),
                &Sha256Digest::from_bytes([88; 32]),
                committed_at,
            )?;
            Ok(())
        });
        rotation_finished_tx.send(outcome).unwrap();
    });
    rotation_started_rx.recv().unwrap();
    assert!(
        rotation_finished_rx
            .recv_timeout(Duration::from_millis(150))
            .is_err(),
        "credential rotation passed the evidence transaction's share locks"
    );

    finish_read_tx.send(()).unwrap();
    assert!(matches!(
        reader_worker.join().unwrap().unwrap(),
        VolumeTransitionEvidenceLoad::Available(_)
    ));
    rotation_finished_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("rotation finishes after evidence commit")
        .unwrap();
    rotation_worker.join().unwrap();

    let old = seed
        .runtime_volume_transition_evidence(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
        )
        .unwrap();
    assert_eq!(
        old,
        VolumeTransitionStoreOutcome::Rejected(VolumeTransitionStoreRejection::IdentityNotEligible)
    );
    let rotated = AuthenticatedNodeCredential::new(
        id("credential-rotated"),
        CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::from_bytes([88; 32]),
        },
    );
    assert!(matches!(
        seed.runtime_volume_transition_evidence(
            &rotated,
            &request,
            &node.active_guest_config_digest,
        )
        .unwrap(),
        VolumeTransitionStoreOutcome::Accepted(VolumeTransitionEvidenceLoad::Available(_))
    ));
}

#[test]
fn authenticated_takeover_response_loss_replays_the_committed_receipt() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");

    store.inject_committed_response_loss_once();
    let error = store
        .runtime_consume_volume_takeover(
            &node.authenticated,
            &node.session,
            &id("takeover-auth-1"),
            &node.active_guest_config_digest,
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    let committed_volume = stored_volume(&store, &owned.volume_id);
    assert_eq!(committed_volume.lease_owner, Some(id("attachment-new")));
    assert!(matches!(
        stored_authorization(&store, &id("takeover-auth-1")).state,
        AuthorizationState::Consumed(_)
    ));

    let replay = store
        .runtime_consume_volume_takeover(
            &node.authenticated,
            &node.session,
            &id("takeover-auth-1"),
            &node.active_guest_config_digest,
        )
        .unwrap();
    let VolumeTransitionStoreOutcome::Accepted(replay) = replay else {
        panic!("committed takeover replay was rejected")
    };
    assert_eq!(replay.resulting_epoch, committed_volume.lease_epoch);
    assert_eq!(replay.resulting_head, committed_volume.head);
    assert_eq!(replay.attachment_id, id("attachment-new"));
}

#[test]
fn evidence_snapshot_rejects_missing_direct_successor_and_split_completion() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap();
    let node = transition_node(&store, "node-new");
    let request = evidence_request("node-new");

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_records
                        SET record=jsonb_set(record, '{last_transition,authorization_id}',
                                             '\"missing-auth\"'::jsonb),
                            last_transition_id='missing-auth'
                      WHERE volume_id=$1",
                    &[&"volume-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = store
        .authority_locking_read_snapshot(|transaction| load_evidence(transaction, &node, &request))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_records
                        SET record=jsonb_set(record, '{last_transition,authorization_id}',
                                             '\"takeover-auth-1\"'::jsonb),
                            last_transition_id='takeover-auth-1'
                      WHERE volume_id=$1",
                    &[&"volume-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    let current = stored_volume(&store, &id("volume-1"));
    let completion = DeleteCompletionReceipt::Normal {
        request: cats_storage::authority::BeginDeleteRequest {
            delete_id: id("delete-split"),
            disk_id: id("disk-1"),
            volume_id: current.volume_id.clone(),
            expected_unowned_epoch: current.lease_epoch,
            expected_head: current.head.clone(),
        },
        deleting_epoch: fence_epoch(current.lease_epoch.get() + 1),
        deleting_head: current.head,
        completed_at: unix_millis(40_000),
    };
    store
        .authority_transaction(|transaction| insert_delete_completion(transaction, &completion))
        .unwrap();
    let error = store
        .authority_locking_read_snapshot(|transaction| load_evidence(transaction, &node, &request))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn takeover_authorized_node_is_immutable_and_wrong_caller_has_zero_writes() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let before_volume = stored_volume(&store, &owned.volume_id);
    let before_authorization = stored_authorization(&store, &id("takeover-auth-1"));

    let error = consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-other")).unwrap_err();
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(stored_volume(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization(&store, &id("takeover-auth-1")),
        before_authorization
    );
}

#[test]
fn evidence_snapshot_returns_disposable_completion_after_rows_are_gone() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let original = disposable_authorization(&owned);
    store
        .authority_transaction(|transaction| insert_authorization(transaction, &original))
        .unwrap();
    let (deleting, consumed, _) = consume_disposable_root_delete(
        &owned,
        None,
        &original,
        &id("delete-auth-1"),
        unix_millis(20_000),
    )
    .unwrap();
    store
        .authority_transaction(|transaction| {
            update_volume(transaction, &deleting)?;
            update_authorization(transaction, &original, &consumed)
        })
        .unwrap();
    let completion =
        complete_disposable_root_delete(&deleting, &consumed, unix_millis(40_000)).unwrap();
    store
        .authority_transaction(|transaction| {
            insert_delete_completion(transaction, &completion)?;
            transaction.execute(
                "DELETE FROM volume_records WHERE volume_id=$1",
                &[&owned.volume_id.as_str()],
            )?;
            Ok(())
        })
        .unwrap();

    let node = transition_node(&store, "node-new");
    let request = evidence_request_for("node-new", "delete-auth-1");
    let loaded = store
        .authority_locking_read_snapshot(|transaction| load_evidence(transaction, &node, &request))
        .unwrap();
    let VolumeTransitionEvidenceLoad::Available(success) = loaded else {
        panic!("disposable evidence unexpectedly unavailable")
    };
    assert_eq!(success.current_volume, None);
    assert_eq!(success.delete_completion, Some(completion));
    assert_eq!(success.authorization, consumed);
    assert_eq!(success.direct_successor_authorization, None);
}

#[test]
fn evidence_snapshot_detects_duplicate_completion_rows_even_without_schema_guard() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let result = consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap();
    let node = transition_node(&store, "node-new");
    store
        .with(|client| {
            client.batch_execute(
                "ALTER TABLE delete_completion_receipts
                   DROP CONSTRAINT delete_completion_receipts_volume_id_key",
            )
        })
        .unwrap();
    store
        .with(|client| {
            client
                .execute(
                    "DELETE FROM volume_records WHERE volume_id=$1",
                    &[&owned.volume_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();
    for (delete_id, disk_id, completed_at) in [
        ("delete-a", "disk-a", 40_000),
        ("delete-b", "disk-b", 40_001),
    ] {
        let expected_unowned_epoch = fence_epoch(result.resulting_epoch.get() + 1);
        let completion = DeleteCompletionReceipt::Normal {
            request: cats_storage::authority::BeginDeleteRequest {
                delete_id: id(delete_id),
                disk_id: id(disk_id),
                volume_id: owned.volume_id.clone(),
                expected_unowned_epoch,
                expected_head: result.resulting_head.clone(),
            },
            deleting_epoch: fence_epoch(expected_unowned_epoch.get() + 1),
            deleting_head: result.resulting_head.clone(),
            completed_at: unix_millis(completed_at),
        };
        store
            .authority_transaction(|transaction| insert_delete_completion(transaction, &completion))
            .unwrap();
    }

    let request = evidence_request("node-new");
    let error = store
        .authority_locking_read_snapshot(|transaction| load_evidence(transaction, &node, &request))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn evidence_repeatable_read_never_mixes_takeover_before_and_after_images() {
    let (_url, seed, reader) = store_pair();
    let owned = acquire_owned_volume(&seed);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&seed, &event, &authorization);
    let node = transition_node(&seed, "node-new");

    let request = evidence_request("node-new");
    let reader_request = request.clone();
    let reader_node = node.clone();
    let (snapshot_tx, snapshot_rx) = mpsc::channel();
    let (continue_tx, continue_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        reader.authority_locking_read_snapshot(move |transaction| {
            // Authenticate and establish the RR snapshot before allowing the
            // writer to commit. The unforgeable context carries that one DB
            // time into the evidence loader.
            let context = match authenticate_evidence_context_in(
                transaction,
                &reader_node.authenticated,
                &reader_request.session,
                &reader_node.active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => context,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    panic!("evidence prefix rejected: {rejection:?}")
                }
            };
            snapshot_tx.send(()).unwrap();
            continue_rx.recv().unwrap();
            load_volume_transition_evidence_in(context, &reader_request)
        })
    });
    snapshot_rx.recv().unwrap();
    let writer = Store::connect_from(&seed.dsn, None).unwrap();
    let writer_node = node.clone();
    let (consume_finished_tx, consume_finished_rx) = mpsc::channel();
    let consume_worker = std::thread::spawn(move || {
        consume_finished_tx
            .send(consume_takeover_with_node(
                &writer,
                &id("takeover-auth-1"),
                &writer_node,
            ))
            .unwrap();
    });
    assert!(
        consume_finished_rx
            .recv_timeout(Duration::from_millis(150))
            .is_err(),
        "takeover mutation passed the evidence transaction's identity share lock"
    );
    continue_tx.send(()).unwrap();

    let VolumeTransitionEvidenceLoad::Available(before) = worker.join().unwrap().unwrap() else {
        panic!("pre-commit snapshot unexpectedly unavailable")
    };
    assert!(matches!(
        before.authorization.state,
        AuthorizationState::Unconsumed
    ));
    assert_eq!(before.current_volume, Some(owned));
    consume_finished_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("takeover finishes after evidence snapshot commits")
        .unwrap();
    consume_worker.join().unwrap();

    let VolumeTransitionEvidenceLoad::Available(after) =
        load_evidence_public(&seed, &node, &request).unwrap()
    else {
        panic!("post-commit snapshot unexpectedly unavailable")
    };
    assert!(matches!(
        after.authorization.state,
        AuthorizationState::Consumed(_)
    ));
    assert_eq!(
        after.current_volume.unwrap().lease_owner,
        Some(id("attachment-new"))
    );
}

#[test]
fn corrupted_authorization_payload_fails_closed_without_writes() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    let authorization_id = id("takeover-auth-1");
    seed_takeover(&store, &event, &authorization);

    // Attachment identities are intentionally not duplicated as projections.
    // Make the closed JSONB payload internally invalid while every projection
    // remains valid and unchanged.
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_authorizations
                        SET record=jsonb_set(
                            record,
                            '{authorization,new_attachment_id}',
                            record #> '{authorization,expected_attachment_id}'
                        )
                      WHERE authorization_id=$1",
                    &[&authorization_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();

    let before_volume = stored_volume(&store, &owned.volume_id);
    let before_event = stored_event(&store, &event.event_id);
    let before_authorization = stored_authorization_row(&store, &authorization_id);

    let error = consume_takeover_as(&store, &authorization_id, &id("node-new")).unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert_eq!(stored_volume(&store, &owned.volume_id), before_volume);
    assert_eq!(stored_event(&store, &event.event_id), before_event);
    assert_eq!(
        stored_authorization_row(&store, &authorization_id),
        before_authorization
    );
}

#[test]
fn rejoin_event_lock_serializes_before_unconsumed_takeover() {
    let (_url, seed, consumer) = store_pair();
    let owned = acquire_owned_volume(&seed);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&seed, &event, &authorization);

    let rejoin = Store::connect_from(&seed.dsn, None).unwrap();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let rejoin_worker = std::thread::spawn(move || {
        rejoin.authority_transaction(move |transaction| {
            let mut event = load_event_for_update(transaction, &id("fence-event-1"))?.unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            event.state = HostFenceEventState::Rejoined;
            update_event(transaction, &event)
        })
    });
    locked_rx.recv().unwrap();
    let consume_worker = std::thread::spawn(move || {
        consume_takeover_as(&consumer, &id("takeover-auth-1"), &id("node-new"))
    });
    release_tx.send(()).unwrap();
    rejoin_worker.join().unwrap().unwrap();
    let error = consume_worker.join().unwrap().unwrap_err();
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(stored_volume(&seed, &owned.volume_id), owned);
    assert!(matches!(
        stored_authorization(&seed, &id("takeover-auth-1")).state,
        AuthorizationState::Unconsumed
    ));
}

#[test]
fn delete_completion_codec_is_exactly_idempotent() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let receipt = DeleteCompletionReceipt::Normal {
        request: cats_storage::authority::BeginDeleteRequest {
            delete_id: id("delete-1"),
            disk_id: id("disk-1"),
            volume_id: id("volume-1"),
            expected_unowned_epoch: fence_epoch(7),
            expected_head: head(4),
        },
        deleting_epoch: fence_epoch(8),
        deleting_head: head(4),
        completed_at: unix_millis(20_000),
    };
    store
        .authority_transaction(|transaction| insert_delete_completion(transaction, &receipt))
        .unwrap();
    store
        .authority_transaction(|transaction| insert_delete_completion(transaction, &receipt))
        .unwrap();
    let stored = store
        .authority_transaction(|transaction| {
            Ok(load_delete_completion_for_update(transaction, &id("delete-1"))?.unwrap())
        })
        .unwrap();
    assert_eq!(stored, receipt);

    let DeleteCompletionReceipt::Normal {
        request,
        deleting_epoch,
        deleting_head,
        ..
    } = &receipt
    else {
        unreachable!()
    };
    let changed = DeleteCompletionReceipt::Normal {
        request: request.clone(),
        deleting_epoch: *deleting_epoch,
        deleting_head: deleting_head.clone(),
        completed_at: unix_millis(20_001),
    };
    let error = store
        .authority_transaction(|transaction| insert_delete_completion(transaction, &changed))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
}

#[test]
fn serialization_and_deadlock_errors_retry_the_whole_closure_with_a_bound() {
    for sqlstate in ["40001", "40P01"] {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let value = store
            .authority_transaction(|transaction| {
                let attempt = observed.fetch_add(1, Ordering::SeqCst);
                if attempt < 2 {
                    transaction.batch_execute(&format!(
                        "DO $$ BEGIN RAISE EXCEPTION 'retry' USING ERRCODE='{sqlstate}'; END $$"
                    ))?;
                }
                Ok(42_u64)
            })
            .unwrap();
        assert_eq!(value, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);
    let error = store
        .authority_transaction::<()>(|transaction| {
            observed.fetch_add(1, Ordering::SeqCst);
            transaction.batch_execute(
                "DO $$ BEGIN RAISE EXCEPTION 'retry' USING ERRCODE='40001'; END $$",
            )?;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        authority_transaction_attempts()
    );
}

#[test]
fn transient_connection_loss_reconnects_and_replays_the_whole_closure() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);
    let value = store
        .authority_transaction(|transaction| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                transaction.batch_execute("SELECT pg_terminate_backend(pg_backend_pid())")?;
            }
            Ok(42_u64)
        })
        .unwrap();
    assert_eq!(value, 42);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_an_active_authority_call_leaves_no_idle_transaction() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Arc::new(Store::connect(&url, None).unwrap());
    seed_volume(&store, &unowned_volume());
    let observer = Store::connect(&url, None).unwrap();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker_store = Arc::clone(&store);
    let task = tokio::spawn(async move {
        worker_store
            .execute(move |store| {
                store.authority_transaction::<()>(move |transaction| {
                    let pid: i32 = transaction
                        .query_one("SELECT pg_backend_pid()", &[])?
                        .try_get(0)?;
                    load_volume_for_update(transaction, &id("volume-1"))?.unwrap();
                    locked_tx.send(pid).unwrap();
                    release_rx.recv().unwrap();
                    Err(AuthorityTransactionError::Domain(
                        cats_storage::authority::AuthorityError::InvalidAuthorization,
                    ))
                })
            })
            .await
    });
    let pid = tokio::task::spawn_blocking(move || locked_rx.recv().unwrap())
        .await
        .unwrap();
    task.abort();
    release_tx.send(()).unwrap();

    let mut released = false;
    for _ in 0..200 {
        let lock_is_free = observer
            .with(|client| {
                client
                    .query_opt(
                        "SELECT volume_id FROM volume_records
                          WHERE volume_id='volume-1' FOR UPDATE NOWAIT",
                        &[],
                    )
                    .map(|_| ())
            })
            .is_ok();
        let state = observer
            .with(|client| {
                client
                    .query_opt("SELECT state FROM pg_stat_activity WHERE pid=$1", &[&pid])
                    .map(|row| row.map(|row| row.get::<_, String>(0)))
            })
            .unwrap();
        if lock_is_free && state.as_deref().is_none_or(|value| value == "idle") {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        released,
        "cancelled call retained a lock or idle transaction"
    );
}

#[test]
fn authority_metrics_have_only_fixed_low_cardinality_labels() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let mut body = String::new();
    metrics_snapshot(&store).append_prometheus(&mut body);
    for label in [
        "outcome=\"committed\"",
        "outcome=\"domain_rejected\"",
        "outcome=\"backend_failed\"",
        "reason=\"serialization\"",
        "reason=\"deadlock\"",
        "reason=\"connection\"",
    ] {
        assert!(
            body.contains(label),
            "missing fixed authority label {label}"
        );
    }
    assert!(!body.contains("volume-1"));
    assert!(!body.contains("takeover-auth-1"));
}
