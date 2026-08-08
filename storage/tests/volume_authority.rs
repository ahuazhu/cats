use cats_storage::authority::*;

const MAX_INTEGER: u64 = i64::MAX as u64;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random_id(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn boot_id(value: u128) -> NodeBootId {
    NodeBootId::new(format!("{value:032x}")).unwrap()
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

fn time(value: u64) -> UnixMillis {
    UnixMillis::new(value).unwrap()
}

fn empty_head() -> RemoteHead {
    RemoteHead {
        generation: generation(0),
        root_hash: None,
        root_object_id: None,
    }
}

fn head(value: u64) -> RemoteHead {
    RemoteHead {
        generation: generation(value),
        root_hash: Some(Sha256Digest::new(format!("sha256:{:064x}", value.max(1))).unwrap()),
        root_object_id: Some(AsciiText::new(format!("roots/{value}")).unwrap()),
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

fn acquire_request(transition: u128) -> NormalAcquireRequest {
    NormalAcquireRequest {
        volume_id: id("volume-1"),
        transition_id: random_id(transition),
        attachment_id: id("attachment-old"),
        expected_unowned_epoch: fence_epoch(7),
        desired_revision: revision(11),
        placement_epoch: epoch(3),
        lease_duration_ms: 5_000,
    }
}

fn acquired_volume() -> VolumeRecord {
    normal_acquire(&unowned_volume(), &acquire_request(1), time(10_000))
        .unwrap()
        .0
}

fn host_fence_event(state: HostFenceEventState) -> HostFenceEvent {
    HostFenceEvent {
        event_id: id("fence-event-1"),
        provider: id("provider-1"),
        immutable_host_id: id("host-1"),
        node_id: id("node-old"),
        expected_node_boot_id: boot_id(1),
        expected_agent_session_epoch: epoch(8),
        fence_attempt_id: id("fence-attempt-1"),
        isolation_state: HostIsolationState::Isolated,
        observed_at: time(12_000),
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
            lease_duration_ms: 6_000,
            not_after: time(30_000),
        }),
        state: AuthorizationState::Unconsumed,
    }
}

fn disposable_authorization(
    volume: &VolumeRecord,
    basis: DisposableDeleteIsolationBasis,
) -> AuthorizationRecord {
    AuthorizationRecord {
        authorization: VolumeAuthorization::DisposableRootDelete(
            DisposableRootDeleteAuthorization {
                authorization_id: id("delete-auth-1"),
                delete_id: id("delete-1"),
                disk_id: id("disk-1"),
                volume_id: volume.volume_id.clone(),
                cat_id: id("cat-1"),
                desired_revision: revision(13),
                placement_epoch: epoch(3),
                expected_attachment_id: volume.lease_owner.clone().unwrap(),
                expected_epoch: volume.lease_epoch,
                expected_head: volume.head.clone(),
                isolation_basis: basis,
                not_after: time(30_000),
            },
        ),
        state: AuthorizationState::Unconsumed,
    }
}

#[test]
fn remote_head_accepts_only_empty_or_complete_tuples() {
    assert!(remote_head_is_valid(&empty_head()));
    assert!(remote_head_is_valid(&head(1)));

    let hash = head(1).root_hash;
    let object = head(1).root_object_id;
    for invalid in [
        RemoteHead {
            generation: generation(0),
            root_hash: hash.clone(),
            root_object_id: None,
        },
        RemoteHead {
            generation: generation(0),
            root_hash: None,
            root_object_id: object.clone(),
        },
        RemoteHead {
            generation: generation(0),
            root_hash: hash.clone(),
            root_object_id: object.clone(),
        },
        RemoteHead {
            generation: generation(1),
            root_hash: None,
            root_object_id: object.clone(),
        },
        RemoteHead {
            generation: generation(1),
            root_hash: hash,
            root_object_id: None,
        },
    ] {
        assert!(!remote_head_is_valid(&invalid));
    }
}

#[test]
fn remote_head_successor_requires_exact_tuple_at_equal_generation() {
    let original = head(4);
    assert!(remote_head_is_same_or_later(&original, &original));
    assert!(remote_head_is_same_or_later(&head(5), &original));
    assert!(!remote_head_is_same_or_later(&head(3), &original));

    let mut changed_hash = original.clone();
    changed_hash.root_hash = head(9).root_hash;
    let mut changed_object = original.clone();
    changed_object.root_object_id = head(9).root_object_id;
    assert!(!remote_head_is_same_or_later(&changed_hash, &original));
    assert!(!remote_head_is_same_or_later(&changed_object, &original));
}

#[test]
fn volume_record_rejects_impossible_owner_and_admin_combinations() {
    let base = unowned_volume();
    for invalid in [
        VolumeRecord {
            lease_expires_at: Some(time(1)),
            ..base.clone()
        },
        VolumeRecord {
            lease_owner: Some(id("attachment-1")),
            ..base.clone()
        },
        VolumeRecord {
            size_bytes: 0,
            ..base.clone()
        },
        VolumeRecord {
            admin_state: VolumeAdminState::Deleting {
                delete_id: id("delete-1"),
            },
            lease_owner: Some(id("attachment-1")),
            lease_expires_at: Some(time(1)),
            ..base.clone()
        },
    ] {
        assert_eq!(
            validate_volume_record(&invalid),
            Err(AuthorityError::BackendUnknown)
        );
    }
}

fn assert_owned_row_is_rejected_before_renew_or_release(record: &VolumeRecord) {
    let before = record.clone();
    let renew = RenewLeaseRequest {
        volume_id: record.volume_id.clone(),
        attachment_id: record.lease_owner.clone().unwrap(),
        expected_epoch: record.lease_epoch,
        lease_duration_ms: 1,
    };
    assert_eq!(
        renew_lease(record, &renew, time(20_000)),
        Err(AuthorityError::BackendUnknown)
    );
    let release_request = ReleaseRequest {
        volume_id: record.volume_id.clone(),
        transition_id: random_id(31),
        attachment_id: record.lease_owner.clone().unwrap(),
        expected_epoch: record.lease_epoch,
    };
    assert_eq!(
        release(record, &release_request),
        Err(AuthorityError::BackendUnknown)
    );
    assert_eq!(record, &before);
}

#[test]
fn acquired_and_takeover_rows_fail_closed_on_zero_expiry_or_epoch() {
    let mut acquired = acquired_volume();
    acquired.lease_expires_at = Some(time(0));
    assert_eq!(
        validate_volume_record(&acquired),
        Err(AuthorityError::BackendUnknown)
    );
    assert_owned_row_is_rejected_before_renew_or_release(&acquired);

    let old_owner = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&old_owner);
    let taken_over = consume_takeover(
        &old_owner,
        &event,
        &authorization,
        &id("takeover-auth-1"),
        time(20_000),
    )
    .unwrap()
    .0;

    let mut zero_expiry = taken_over.clone();
    zero_expiry.lease_expires_at = Some(time(0));
    assert_eq!(
        validate_volume_record(&zero_expiry),
        Err(AuthorityError::BackendUnknown)
    );
    assert_owned_row_is_rejected_before_renew_or_release(&zero_expiry);

    let mut zero_epoch = taken_over;
    zero_epoch.lease_epoch = fence_epoch(0);
    assert_eq!(
        validate_volume_record(&zero_epoch),
        Err(AuthorityError::BackendUnknown)
    );
    assert_owned_row_is_rejected_before_renew_or_release(&zero_epoch);
}

#[test]
fn disposable_deleting_epoch_zero_fails_before_completion() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = disposable_authorization(
        &owned,
        DisposableDeleteIsolationBasis::HostFenceEvent {
            event_id: event.event_id.clone(),
        },
    );
    let (mut deleting, consumed, _) = consume_disposable_root_delete(
        &owned,
        Some(&event),
        &authorization,
        &id("delete-auth-1"),
        time(20_000),
    )
    .unwrap();
    deleting.lease_epoch = fence_epoch(0);
    let before_volume = deleting.clone();
    let before_authorization = consumed.clone();
    assert_eq!(
        validate_volume_record(&deleting),
        Err(AuthorityError::BackendUnknown)
    );
    assert_eq!(
        complete_disposable_root_delete(&deleting, &consumed, time(40_000)),
        Err(AuthorityError::BackendUnknown)
    );
    assert_eq!(deleting, before_volume);
    assert_eq!(consumed, before_authorization);
}

#[test]
fn normal_acquire_replays_the_original_absolute_expiry() {
    let base = unowned_volume();
    let request = acquire_request(1);
    let (acquired, first) = normal_acquire(&base, &request, time(10_000)).unwrap();
    assert_eq!(first.resulting_epoch, fence_epoch(8));
    assert_eq!(first.resulting_head, base.head);
    assert_eq!(first.lease_expires_at, time(15_000));

    let (replayed, replay) = normal_acquire(&acquired, &request, time(29_000)).unwrap();
    assert_eq!(replayed, acquired);
    assert_eq!(replay, first);
}

#[test]
fn normal_acquire_same_id_with_any_payload_change_is_stale() {
    let request = acquire_request(1);
    let acquired = normal_acquire(&unowned_volume(), &request, time(10_000))
        .unwrap()
        .0;
    let changed = [
        NormalAcquireRequest {
            volume_id: id("volume-2"),
            ..request.clone()
        },
        NormalAcquireRequest {
            attachment_id: id("attachment-other"),
            ..request.clone()
        },
        NormalAcquireRequest {
            expected_unowned_epoch: fence_epoch(6),
            ..request.clone()
        },
        NormalAcquireRequest {
            desired_revision: revision(12),
            ..request.clone()
        },
        NormalAcquireRequest {
            placement_epoch: epoch(4),
            ..request.clone()
        },
        NormalAcquireRequest {
            lease_duration_ms: 5_001,
            ..request
        },
    ];
    for stale in changed {
        assert_eq!(
            normal_acquire(&acquired, &stale, time(20_000)),
            Err(AuthorityError::StaleTransition)
        );
    }
}

#[test]
fn expired_owner_is_still_another_writer() {
    let owned = acquired_volume();
    let mut request = acquire_request(2);
    request.expected_unowned_epoch = owned.lease_epoch;
    request.attachment_id = id("attachment-new");
    assert_eq!(
        normal_acquire(&owned, &request, time(1_000_000)),
        Err(AuthorityError::OtherWriter)
    );

    request.attachment_id = owned.lease_owner.clone().unwrap();
    assert_eq!(
        normal_acquire(&owned, &request, time(1_000_000)),
        Err(AuthorityError::OtherWriter)
    );
}

#[test]
fn lease_duration_and_db_time_overflow_are_rejected_without_change() {
    let base = unowned_volume();
    for (duration, now) in [(0, 1), (MAX_INTEGER + 1, 1), (1, MAX_INTEGER)] {
        let mut request = acquire_request(1);
        request.lease_duration_ms = duration;
        assert_eq!(
            normal_acquire(&base, &request, time(now)),
            Err(AuthorityError::InvalidLeaseDuration)
        );
        assert_eq!(base, unowned_volume());
    }
}

#[test]
fn renew_after_expiry_keeps_owner_epoch_and_transition() {
    let owned = acquired_volume();
    let request = RenewLeaseRequest {
        volume_id: owned.volume_id.clone(),
        attachment_id: owned.lease_owner.clone().unwrap(),
        expected_epoch: owned.lease_epoch,
        lease_duration_ms: 100,
    };
    let (renewed, result) = renew_lease(&owned, &request, time(1_000_000)).unwrap();
    assert_eq!(renewed.lease_owner, owned.lease_owner);
    assert_eq!(renewed.lease_epoch, owned.lease_epoch);
    assert_eq!(renewed.head, owned.head);
    assert_eq!(renewed.last_transition, owned.last_transition);
    assert_eq!(result.lease_expires_at, time(1_000_100));

    let mut wrong = request;
    wrong.attachment_id = id("attachment-other");
    assert_eq!(
        renew_lease(&owned, &wrong, time(20_000)),
        Err(AuthorityError::Fenced)
    );
}

#[test]
fn release_is_exactly_replayable_and_fences_late_acquire() {
    let owned = acquired_volume();
    let request = ReleaseRequest {
        volume_id: owned.volume_id.clone(),
        transition_id: random_id(2),
        attachment_id: owned.lease_owner.clone().unwrap(),
        expected_epoch: owned.lease_epoch,
    };
    let (released, first) = release(&owned, &request).unwrap();
    assert_eq!(released.lease_owner, None);
    assert_eq!(released.lease_expires_at, None);
    assert_eq!(released.lease_epoch, fence_epoch(9));
    assert_eq!(release(&released, &request).unwrap().1, first);

    let mut stale = request.clone();
    stale.attachment_id = id("attachment-other");
    assert_eq!(
        release(&released, &stale),
        Err(AuthorityError::StaleTransition)
    );
    assert_eq!(
        normal_acquire(&released, &acquire_request(1), time(20_000)),
        Err(AuthorityError::Fenced)
    );
}

#[test]
fn normal_transition_identity_cannot_cross_acquire_and_release_variants() {
    let owned = acquired_volume();
    let request = ReleaseRequest {
        volume_id: owned.volume_id.clone(),
        transition_id: acquire_request(1).transition_id,
        attachment_id: owned.lease_owner.clone().unwrap(),
        expected_epoch: owned.lease_epoch,
    };
    assert_eq!(
        release(&owned, &request),
        Err(AuthorityError::StaleTransition)
    );
}

#[test]
fn takeover_consumes_one_server_side_authorization() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    let (taken_over, consumed, result) = consume_takeover(
        &owned,
        &event,
        &authorization,
        &id("takeover-auth-1"),
        time(20_000),
    )
    .unwrap();

    assert_eq!(taken_over.lease_owner, Some(id("attachment-new")));
    assert_eq!(taken_over.lease_epoch, fence_epoch(9));
    assert_eq!(taken_over.head, owned.head);
    assert_eq!(result.lease_expires_at, time(26_000));
    assert!(matches!(
        taken_over.last_transition,
        Some(LastVolumeTransition::Takeover { authorization_id })
            if authorization_id == id("takeover-auth-1")
    ));
    assert!(matches!(consumed.state, AuthorizationState::Consumed(_)));
}

#[test]
fn takeover_keeps_the_current_locked_head_without_a_second_head_claim() {
    let mut owned = acquired_volume();
    owned.head = head(5);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    let (taken_over, _, result) = consume_takeover(
        &owned,
        &event,
        &authorization,
        &id("takeover-auth-1"),
        time(20_000),
    )
    .unwrap();
    assert_eq!(taken_over.head, head(5));
    assert_eq!(result.resulting_head, head(5));
}

#[test]
fn consumed_takeover_replays_after_event_rejoined() {
    let owned = acquired_volume();
    let active = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    let (taken_over, consumed, first) = consume_takeover(
        &owned,
        &active,
        &authorization,
        &id("takeover-auth-1"),
        time(20_000),
    )
    .unwrap();
    let rejoined = host_fence_event(HostFenceEventState::Rejoined);
    let (unchanged, same_row, replay) = consume_takeover(
        &taken_over,
        &rejoined,
        &consumed,
        &id("takeover-auth-1"),
        time(29_000),
    )
    .unwrap();
    assert_eq!(unchanged, taken_over);
    assert_eq!(same_row, consumed);
    assert_eq!(replay, first);
}

#[test]
fn unconsumed_takeover_rejects_expiry_rejoin_and_wrong_binding() {
    let owned = acquired_volume();
    let authorization = takeover_authorization(&owned);
    for (event, now) in [
        (host_fence_event(HostFenceEventState::Rejoined), 20_000),
        (host_fence_event(HostFenceEventState::Active), 30_001),
    ] {
        assert_eq!(
            consume_takeover(
                &owned,
                &event,
                &authorization,
                &id("takeover-auth-1"),
                time(now),
            ),
            Err(AuthorityError::InvalidAuthorization)
        );
    }

    let mut wrong_event = host_fence_event(HostFenceEventState::Active);
    wrong_event.event_id = id("fence-event-other");
    assert_eq!(
        consume_takeover(
            &owned,
            &wrong_event,
            &authorization,
            &id("takeover-auth-1"),
            time(20_000),
        ),
        Err(AuthorityError::InvalidAuthorization)
    );
}

#[test]
fn takeover_invalid_duration_is_typed_and_zero_side_effect() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let mut authorization = takeover_authorization(&owned);
    let VolumeAuthorization::Takeover(payload) = &mut authorization.authorization else {
        unreachable!()
    };
    payload.lease_duration_ms = 0;
    assert_eq!(
        consume_takeover(
            &owned,
            &event,
            &authorization,
            &id("takeover-auth-1"),
            time(20_000),
        ),
        Err(AuthorityError::InvalidLeaseDuration)
    );
    assert_eq!(owned, acquired_volume());
    assert!(matches!(
        authorization.state,
        AuthorizationState::Unconsumed
    ));
}

#[test]
fn takeover_cannot_replace_an_attachment_with_itself() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let mut authorization = takeover_authorization(&owned);
    let VolumeAuthorization::Takeover(payload) = &mut authorization.authorization else {
        unreachable!()
    };
    payload.new_attachment_id = payload.expected_attachment_id.clone();

    let before_volume = owned.clone();
    let before_event = event.clone();
    let before_authorization = authorization.clone();
    assert_eq!(
        validate_authorization_record(&authorization),
        Err(AuthorityError::InvalidAuthorization)
    );
    assert_eq!(
        consume_takeover(
            &owned,
            &event,
            &authorization,
            &id("takeover-auth-1"),
            time(20_000),
        ),
        Err(AuthorityError::InvalidAuthorization)
    );
    assert_eq!(owned, before_volume);
    assert_eq!(event, before_event);
    assert_eq!(authorization, before_authorization);
}

#[test]
fn authorization_receipt_payload_mismatch_is_backend_unknown() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    let (_, mut consumed, _) = consume_takeover(
        &owned,
        &event,
        &authorization,
        &id("takeover-auth-1"),
        time(20_000),
    )
    .unwrap();
    let AuthorizationState::Consumed(consumed_receipt) = &mut consumed.state else {
        unreachable!()
    };
    let AuthorizationConsumedReceipt::Takeover(receipt) = consumed_receipt.as_mut() else {
        unreachable!()
    };
    receipt.volume_id = id("volume-other");
    assert_eq!(
        validate_authorization_record(&consumed),
        Err(AuthorityError::BackendUnknown)
    );
}

#[test]
fn disposable_delete_moves_owned_directly_to_deleting() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = disposable_authorization(
        &owned,
        DisposableDeleteIsolationBasis::HostFenceEvent {
            event_id: event.event_id.clone(),
        },
    );
    let (deleting, consumed, receipt) = consume_disposable_root_delete(
        &owned,
        Some(&event),
        &authorization,
        &id("delete-auth-1"),
        time(20_000),
    )
    .unwrap();
    assert!(matches!(
        deleting.admin_state,
        VolumeAdminState::Deleting { ref delete_id } if delete_id == &id("delete-1")
    ));
    assert_eq!(deleting.lease_owner, None);
    assert_eq!(deleting.lease_expires_at, None);
    assert_eq!(deleting.lease_epoch, fence_epoch(9));
    assert_eq!(receipt.prior_attachment_id, id("attachment-old"));

    let rejoined = host_fence_event(HostFenceEventState::Rejoined);
    let replay = consume_disposable_root_delete(
        &deleting,
        Some(&rejoined),
        &consumed,
        &id("delete-auth-1"),
        time(29_000),
    )
    .unwrap();
    assert_eq!(replay.0, deleting);
    assert_eq!(replay.1, consumed);
    assert_eq!(replay.2, receipt);
}

#[test]
fn disposable_runtime_stopped_and_host_fence_bases_cannot_be_confused() {
    let owned = acquired_volume();
    let stopped = disposable_authorization(
        &owned,
        DisposableDeleteIsolationBasis::RuntimeStopped {
            node_id: id("node-old"),
            agent_session_epoch: epoch(8),
            runtime_incarnation: random_id(5),
            observation_id: random_id(6),
        },
    );
    assert!(consume_disposable_root_delete(
        &owned,
        None,
        &stopped,
        &id("delete-auth-1"),
        time(20_000),
    )
    .is_ok());
    assert_eq!(
        consume_disposable_root_delete(
            &owned,
            Some(&host_fence_event(HostFenceEventState::Active)),
            &stopped,
            &id("delete-auth-1"),
            time(20_000),
        ),
        Err(AuthorityError::InvalidAuthorization)
    );
}

#[test]
fn begin_delete_replays_exact_request_and_rejects_conflicts() {
    let base = unowned_volume();
    let request = BeginDeleteRequest {
        delete_id: id("delete-1"),
        disk_id: id("disk-1"),
        volume_id: base.volume_id.clone(),
        expected_unowned_epoch: base.lease_epoch,
        expected_head: base.head.clone(),
    };
    let (deleting, result) = begin_delete(&base, &request).unwrap();
    assert_eq!(begin_delete(&deleting, &request).unwrap().1, result);

    let mut changed = request.clone();
    changed.disk_id = id("disk-other");
    assert_eq!(
        begin_delete(&deleting, &changed),
        Err(AuthorityError::StaleTransition)
    );

    let mut wrong_head = request;
    wrong_head.delete_id = id("delete-2");
    wrong_head.expected_head = head(3);
    assert_eq!(
        begin_delete(&base, &wrong_head),
        Err(AuthorityError::HeadConflict)
    );
}

#[test]
fn deleting_state_rejects_all_writer_transitions() {
    let base = unowned_volume();
    let delete = BeginDeleteRequest {
        delete_id: id("delete-1"),
        disk_id: id("disk-1"),
        volume_id: base.volume_id.clone(),
        expected_unowned_epoch: base.lease_epoch,
        expected_head: base.head.clone(),
    };
    let deleting = begin_delete(&base, &delete).unwrap().0;
    let mut acquire = acquire_request(9);
    acquire.expected_unowned_epoch = deleting.lease_epoch;
    assert_eq!(
        normal_acquire(&deleting, &acquire, time(20_000)),
        Err(AuthorityError::AdminBusy)
    );
    let renew = RenewLeaseRequest {
        volume_id: deleting.volume_id.clone(),
        attachment_id: id("attachment-old"),
        expected_epoch: deleting.lease_epoch,
        lease_duration_ms: 1,
    };
    assert_eq!(
        renew_lease(&deleting, &renew, time(20_000)),
        Err(AuthorityError::AdminBusy)
    );
}

#[test]
fn table_outside_transitions_fail_closed() {
    let unowned = unowned_volume();
    let renew = RenewLeaseRequest {
        volume_id: unowned.volume_id.clone(),
        attachment_id: id("attachment-old"),
        expected_epoch: unowned.lease_epoch,
        lease_duration_ms: 1,
    };
    assert_eq!(
        renew_lease(&unowned, &renew, time(20_000)),
        Err(AuthorityError::Fenced)
    );
    let release_request = ReleaseRequest {
        volume_id: unowned.volume_id.clone(),
        transition_id: random_id(9),
        attachment_id: id("attachment-old"),
        expected_epoch: unowned.lease_epoch,
    };
    assert_eq!(
        release(&unowned, &release_request),
        Err(AuthorityError::Fenced)
    );

    let owned = acquired_volume();
    let begin = BeginDeleteRequest {
        delete_id: id("delete-1"),
        disk_id: id("disk-1"),
        volume_id: owned.volume_id.clone(),
        expected_unowned_epoch: owned.lease_epoch,
        expected_head: owned.head.clone(),
    };
    assert_eq!(
        begin_delete(&owned, &begin),
        Err(AuthorityError::OtherWriter)
    );

    let event = host_fence_event(HostFenceEventState::Active);
    let takeover = takeover_authorization(&owned);
    assert_eq!(
        consume_takeover(
            &unowned,
            &event,
            &takeover,
            &id("takeover-auth-1"),
            time(20_000),
        ),
        Err(AuthorityError::InvalidAuthorization)
    );
    let disposable = disposable_authorization(
        &owned,
        DisposableDeleteIsolationBasis::HostFenceEvent {
            event_id: event.event_id.clone(),
        },
    );
    assert_eq!(
        consume_disposable_root_delete(
            &unowned,
            Some(&event),
            &disposable,
            &id("delete-auth-1"),
            time(20_000),
        ),
        Err(AuthorityError::InvalidAuthorization)
    );
}

#[test]
fn delete_completion_receipts_are_closed_and_replayable() {
    let base = unowned_volume();
    let request = BeginDeleteRequest {
        delete_id: id("delete-1"),
        disk_id: id("disk-1"),
        volume_id: base.volume_id.clone(),
        expected_unowned_epoch: base.lease_epoch,
        expected_head: base.head.clone(),
    };
    let (deleting, direct) = begin_delete(&base, &request).unwrap();
    let receipt = complete_normal_delete(&deleting, time(40_000)).unwrap();
    assert_eq!(
        replay_completed_normal_delete(&request, &receipt).unwrap(),
        direct
    );

    let mut changed = request.clone();
    changed.disk_id = id("disk-other");
    assert_eq!(
        replay_completed_normal_delete(&changed, &receipt),
        Err(AuthorityError::StaleTransition)
    );
    changed.delete_id = id("delete-other");
    assert_eq!(
        replay_completed_normal_delete(&changed, &receipt),
        Err(AuthorityError::NotFound)
    );
}

#[test]
fn disposable_completion_reconnects_to_the_unique_consumed_receipt() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = disposable_authorization(
        &owned,
        DisposableDeleteIsolationBasis::HostFenceEvent {
            event_id: event.event_id.clone(),
        },
    );
    let (deleting, consumed, direct) = consume_disposable_root_delete(
        &owned,
        Some(&event),
        &authorization,
        &id("delete-auth-1"),
        time(20_000),
    )
    .unwrap();
    let completion = complete_disposable_root_delete(&deleting, &consumed, time(40_000)).unwrap();
    assert_eq!(
        completion,
        DeleteCompletionReceipt::DisposableRoot {
            disk_id: direct.disk_id,
            volume_id: direct.volume_id,
            delete_id: direct.delete_id,
            authorization_id: direct.authorization_id,
            prior_attachment_id: direct.prior_attachment_id,
            deleting_epoch: direct.resulting_epoch,
            deleting_head: direct.resulting_head,
            completed_at: time(40_000),
        }
    );
}

#[test]
fn every_epoch_changing_transition_fails_at_maximum_epoch() {
    let mut unowned = unowned_volume();
    unowned.lease_epoch = fence_epoch(MAX_INTEGER);
    let mut acquire = acquire_request(2);
    acquire.expected_unowned_epoch = unowned.lease_epoch;
    assert_eq!(
        normal_acquire(&unowned, &acquire, time(10_000)),
        Err(AuthorityError::EpochExhausted)
    );
    let delete = BeginDeleteRequest {
        delete_id: id("delete-1"),
        disk_id: id("disk-1"),
        volume_id: unowned.volume_id.clone(),
        expected_unowned_epoch: unowned.lease_epoch,
        expected_head: unowned.head.clone(),
    };
    assert_eq!(
        begin_delete(&unowned, &delete),
        Err(AuthorityError::EpochExhausted)
    );

    let mut almost_max = unowned_volume();
    almost_max.lease_epoch = fence_epoch(MAX_INTEGER - 1);
    acquire.expected_unowned_epoch = almost_max.lease_epoch;
    let owned = normal_acquire(&almost_max, &acquire, time(10_000))
        .unwrap()
        .0;
    let release_request = ReleaseRequest {
        volume_id: owned.volume_id.clone(),
        transition_id: random_id(3),
        attachment_id: owned.lease_owner.clone().unwrap(),
        expected_epoch: owned.lease_epoch,
    };
    assert_eq!(
        release(&owned, &release_request),
        Err(AuthorityError::EpochExhausted)
    );

    let event = host_fence_event(HostFenceEventState::Active);
    let takeover = takeover_authorization(&owned);
    assert_eq!(
        consume_takeover(
            &owned,
            &event,
            &takeover,
            &id("takeover-auth-1"),
            time(20_000),
        ),
        Err(AuthorityError::EpochExhausted)
    );
    let disposable = disposable_authorization(
        &owned,
        DisposableDeleteIsolationBasis::HostFenceEvent {
            event_id: event.event_id.clone(),
        },
    );
    assert_eq!(
        consume_disposable_root_delete(
            &owned,
            Some(&event),
            &disposable,
            &id("delete-auth-1"),
            time(20_000),
        ),
        Err(AuthorityError::EpochExhausted)
    );
}

#[test]
fn wrong_owner_attachment_epoch_and_transition_are_zero_side_effect() {
    let owned = acquired_volume();
    let before = owned.clone();
    let cases = [
        ReleaseRequest {
            volume_id: owned.volume_id.clone(),
            transition_id: random_id(2),
            attachment_id: id("attachment-other"),
            expected_epoch: owned.lease_epoch,
        },
        ReleaseRequest {
            volume_id: owned.volume_id.clone(),
            transition_id: random_id(3),
            attachment_id: owned.lease_owner.clone().unwrap(),
            expected_epoch: fence_epoch(7),
        },
    ];
    for request in cases {
        assert_eq!(release(&owned, &request), Err(AuthorityError::Fenced));
        assert_eq!(owned, before);
    }
}
