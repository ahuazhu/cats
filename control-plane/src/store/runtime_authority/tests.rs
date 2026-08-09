use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use cats_api::error::ErrorCode;
use cats_storage::authority::{
    AsciiText, AuthorizationRecord, AuthorizationState, DeleteCompletionReceipt, Epoch, FenceEpoch,
    Generation, HostFenceEvent, HostFenceEventState, HostIsolationState, Id, NormalAcquireRequest,
    RandomId128, ReleaseRequest, RemoteHead, Revision, Sha256Digest, UnixMillis, VolumeAdminState,
    VolumeAuthorization, VolumeDurability, VolumeRecord, VolumeTakeoverAuthorization,
};

use super::rows::{
    insert_authorization, insert_delete_completion, insert_event, insert_volume,
    load_authorization_for_update, load_delete_completion_for_update, load_event_for_update,
    load_volume_for_update, update_event,
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
    let error = store
        .consume_volume_takeover(&id("takeover-auth-1"))
        .unwrap_err();
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
    let first = store
        .consume_volume_takeover(&id("takeover-auth-1"))
        .unwrap();
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
        store
            .consume_volume_takeover(&id("takeover-auth-1"))
            .unwrap(),
        first
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

    let error = store
        .consume_volume_takeover(&authorization_id)
        .unwrap_err();
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
    let consume_worker =
        std::thread::spawn(move || consumer.consume_volume_takeover(&id("takeover-auth-1")));
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
