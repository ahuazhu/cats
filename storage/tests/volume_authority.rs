use cats_storage::authority::*;

const MAX_INTEGER: u64 = i64::MAX as u64;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random_id(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
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
        attachment_id: id("attachment-a"),
        expected_unowned_epoch: fence_epoch(7),
        placement_epoch: epoch(3),
        lease_duration_ms: 5_000,
    }
}

fn acquired_volume() -> (VolumeRecord, NormalAcquireRequest, NormalAcquireResult) {
    let request = acquire_request(1);
    let (record, result) = normal_acquire(&unowned_volume(), &request, time(10_000)).unwrap();
    (record, request, result)
}

fn snapshot_restore_request(volume: &VolumeRecord) -> SnapshotRestoreRequest {
    SnapshotRestoreRequest {
        snapshot_id: id("snapshot-1"),
        disk_id: id("disk-1"),
        volume_id: volume.volume_id.clone(),
        expected_size_bytes: volume.size_bytes,
        expected_unowned_epoch: volume.lease_epoch,
        expected_head: volume.head.clone(),
        snapshot_head: head(2),
    }
}

fn serving_attachment() -> (AuthorizedServingAttachment, VolumeRecord) {
    let (record, request, result) = acquired_volume();
    let attachment = authorized_serving_attachment_from_direct_acquire(DirectAcquireServingInput {
        node_id: id("node-a"),
        size_bytes: record.size_bytes,
        durability: record.durability,
        request,
        result,
        current_head: record.head.clone(),
        current_lease_expires_at: record.lease_expires_at.unwrap(),
    })
    .unwrap();
    (attachment, record)
}

#[test]
fn direct_serving_attachment_binds_acquire_and_current_authority() {
    let (attachment, record) = serving_attachment();
    validate_authorized_serving_attachment(&attachment).unwrap();
    validate_authorized_serving_record(&record, &attachment, Some(attachment.lease_expires_at))
        .unwrap();

    let mut wrong_transition = attachment.clone();
    wrong_transition.identity.acquire_origin = AcquireOrigin::Normal {
        transition_id: random_id(99),
    };
    assert_eq!(
        validate_authorized_serving_attachment(&wrong_transition),
        Err(AuthorityError::BackendUnknown)
    );

    let mut wrong_duration = attachment.clone();
    wrong_duration.lease_duration_ms += 1;
    assert_eq!(
        validate_authorized_serving_attachment(&wrong_duration),
        Err(AuthorityError::BackendUnknown)
    );

    let mut published = record.clone();
    published.head = head(5);
    validate_authorized_serving_record(&published, &attachment, None).unwrap();

    let mut divergent = record.clone();
    divergent.head.root_hash = Some(Sha256Digest::from_bytes([0xaa; 32]));
    assert_eq!(
        validate_authorized_serving_record(&divergent, &attachment, None),
        Err(AuthorityError::BackendUnknown)
    );

    let mut stale = record;
    stale.lease_expires_at = Some(time(14_999));
    assert_eq!(
        validate_authorized_serving_record(&stale, &attachment, None),
        Err(AuthorityError::BackendUnknown)
    );
}

#[test]
fn direct_serving_attachment_retains_acquire_across_renewal() {
    let (initial, record) = serving_attachment();
    let (renewed_record, renewal) = renew_lease(
        &record,
        &RenewLeaseRequest {
            volume_id: initial.identity.volume_id.clone(),
            attachment_id: initial.identity.attachment_id.clone(),
            expected_epoch: initial.identity.attachment_epoch,
            lease_duration_ms: initial.lease_duration_ms(),
        },
        time(20_000),
    )
    .unwrap();
    let renewed = authorized_serving_attachment_from_direct_acquire(DirectAcquireServingInput {
        node_id: initial.identity.node_id.clone(),
        size_bytes: initial.size_bytes,
        durability: initial.durability,
        request: initial.acquire_request.clone(),
        result: initial.acquire_result.clone(),
        current_head: renewed_record.head.clone(),
        current_lease_expires_at: renewal.lease_expires_at,
    })
    .unwrap();

    assert_eq!(renewed.acquire_request, initial.acquire_request);
    assert_eq!(renewed.acquire_result, initial.acquire_result);
    assert_eq!(renewed.lease_expires_at, time(25_000));
    validate_authorized_serving_record(&renewed_record, &renewed, Some(time(25_000))).unwrap();
}

#[test]
fn remote_heads_require_complete_tuples_and_exact_equal_generation() {
    assert!(remote_head_is_valid(&empty_head()));
    assert!(remote_head_is_valid(&head(1)));

    let mut invalid_empty = empty_head();
    invalid_empty.root_hash = Some(Sha256Digest::from_bytes([1; 32]));
    assert!(!remote_head_is_valid(&invalid_empty));

    let mut incomplete = head(1);
    incomplete.root_object_id = None;
    assert!(!remote_head_is_valid(&incomplete));

    assert!(remote_head_is_same_or_later(&head(5), &head(4)));
    assert!(remote_head_is_same_or_later(&head(4), &head(4)));
    let mut divergent = head(4);
    divergent.root_hash = Some(Sha256Digest::from_bytes([0xbb; 32]));
    assert!(!remote_head_is_same_or_later(&divergent, &head(4)));
    assert!(!remote_head_is_same_or_later(&head(3), &head(4)));
}

#[test]
fn volume_record_rejects_impossible_owner_and_admin_states() {
    validate_volume_record(&unowned_volume()).unwrap();
    let (owned, _, _) = acquired_volume();
    validate_volume_record(&owned).unwrap();

    let mut missing_expiry = owned.clone();
    missing_expiry.lease_expires_at = None;
    assert_eq!(
        validate_volume_record(&missing_expiry),
        Err(AuthorityError::BackendUnknown)
    );

    let mut zero_epoch = owned.clone();
    zero_epoch.lease_epoch = fence_epoch(0);
    assert_eq!(
        validate_volume_record(&zero_epoch),
        Err(AuthorityError::BackendUnknown)
    );

    let mut deleting_with_owner = owned;
    deleting_with_owner.admin_state = VolumeAdminState::Deleting {
        delete_id: id("delete-1"),
    };
    assert_eq!(
        validate_volume_record(&deleting_with_owner),
        Err(AuthorityError::BackendUnknown)
    );
}

#[test]
fn normal_acquire_replays_exact_result_and_never_steals_an_owner() {
    let request = acquire_request(1);
    let (owned, first) = normal_acquire(&unowned_volume(), &request, time(10_000)).unwrap();
    assert_eq!(first.lease_expires_at, time(15_000));

    let (replayed, replay) = normal_acquire(&owned, &request, time(29_000)).unwrap();
    assert_eq!(replayed, owned);
    assert_eq!(replay, first);

    let mut changed = request.clone();
    changed.placement_epoch = epoch(4);
    assert_eq!(
        normal_acquire(&owned, &changed, time(20_000)),
        Err(AuthorityError::StaleTransition)
    );

    let mut different = acquire_request(2);
    different.attachment_id = id("attachment-b");
    assert_eq!(
        normal_acquire(&owned, &different, time(1_000_000)),
        Err(AuthorityError::OtherWriter)
    );
}

#[test]
fn lease_duration_and_clock_overflow_are_zero_side_effect() {
    let mut zero = acquire_request(1);
    zero.lease_duration_ms = 0;
    assert_eq!(
        normal_acquire(&unowned_volume(), &zero, time(10)),
        Err(AuthorityError::InvalidLeaseDuration)
    );

    let request = acquire_request(1);
    assert_eq!(
        normal_acquire(&unowned_volume(), &request, time(MAX_INTEGER - 1)),
        Err(AuthorityError::InvalidLeaseDuration)
    );

    let (owned, _, _) = acquired_volume();
    assert_eq!(
        renew_lease(
            &owned,
            &RenewLeaseRequest {
                volume_id: owned.volume_id.clone(),
                attachment_id: owned.lease_owner.clone().unwrap(),
                expected_epoch: owned.lease_epoch,
                lease_duration_ms: 5_000,
            },
            time(MAX_INTEGER - 1),
        ),
        Err(AuthorityError::InvalidLeaseDuration)
    );
}

#[test]
fn renewal_uses_exact_owner_epoch_even_after_expiry() {
    let (owned, _, _) = acquired_volume();
    let transition = owned.last_transition.clone();
    let request = RenewLeaseRequest {
        volume_id: owned.volume_id.clone(),
        attachment_id: owned.lease_owner.clone().unwrap(),
        expected_epoch: owned.lease_epoch,
        lease_duration_ms: 5_000,
    };
    let (renewed, result) = renew_lease(&owned, &request, time(50_000)).unwrap();
    assert_eq!(result.lease_expires_at, time(55_000));
    assert_eq!(renewed.last_transition, transition);
    assert_eq!(renewed.lease_epoch, owned.lease_epoch);

    let mut wrong = request;
    wrong.attachment_id = id("attachment-b");
    assert_eq!(
        renew_lease(&owned, &wrong, time(20_000)),
        Err(AuthorityError::Fenced)
    );
}

#[test]
fn release_is_exactly_replayable_and_fences_late_acquire() {
    let (owned, _, _) = acquired_volume();
    let request = ReleaseRequest {
        volume_id: owned.volume_id.clone(),
        transition_id: random_id(2),
        attachment_id: owned.lease_owner.clone().unwrap(),
        expected_epoch: owned.lease_epoch,
    };
    let (released, first) = release(&owned, &request).unwrap();
    assert!(released.lease_owner.is_none());
    assert_eq!(released.lease_epoch, fence_epoch(9));

    let (replayed, replay) = release(&released, &request).unwrap();
    assert_eq!(replayed, released);
    assert_eq!(replay, first);

    let mut stale_acquire = acquire_request(3);
    stale_acquire.expected_unowned_epoch = fence_epoch(7);
    assert_eq!(
        normal_acquire(&released, &stale_acquire, time(20_000)),
        Err(AuthorityError::Fenced)
    );

    let mut reused_id = acquire_request(2);
    reused_id.expected_unowned_epoch = released.lease_epoch;
    assert_eq!(
        normal_acquire(&released, &reused_id, time(20_000)),
        Err(AuthorityError::StaleTransition)
    );
}

#[test]
fn begin_delete_is_exact_and_blocks_all_writer_transitions() {
    let base = unowned_volume();
    let request = BeginDeleteRequest {
        delete_id: id("delete-1"),
        disk_id: id("disk-1"),
        volume_id: base.volume_id.clone(),
        expected_unowned_epoch: base.lease_epoch,
        expected_head: base.head.clone(),
    };
    let (deleting, first) = begin_delete(&base, &request).unwrap();
    assert!(matches!(
        deleting.admin_state,
        VolumeAdminState::Deleting { .. }
    ));

    let (replayed, replay) = begin_delete(&deleting, &request).unwrap();
    assert_eq!(replayed, deleting);
    assert_eq!(replay, first);

    let mut changed = request.clone();
    changed.disk_id = id("disk-2");
    assert_eq!(
        begin_delete(&deleting, &changed),
        Err(AuthorityError::StaleTransition)
    );

    let mut wrong_head = request.clone();
    wrong_head.delete_id = id("delete-2");
    wrong_head.expected_head = head(5);
    assert_eq!(
        begin_delete(&base, &wrong_head),
        Err(AuthorityError::HeadConflict)
    );

    let (owned, _, _) = acquired_volume();
    let mut owned_delete = request;
    owned_delete.expected_unowned_epoch = owned.lease_epoch;
    assert_eq!(
        begin_delete(&owned, &owned_delete),
        Err(AuthorityError::OtherWriter)
    );

    let acquire = NormalAcquireRequest {
        expected_unowned_epoch: deleting.lease_epoch,
        ..acquire_request(9)
    };
    assert_eq!(
        normal_acquire(&deleting, &acquire, time(20_000)),
        Err(AuthorityError::AdminBusy)
    );
}

#[test]
fn snapshot_restore_republishes_a_captured_root_at_a_new_generation_and_epoch() {
    let base = unowned_volume();
    let request = snapshot_restore_request(&base);
    let (restored, result) = restore_snapshot(&base, &request).unwrap();

    let expected_head = RemoteHead {
        generation: generation(5),
        root_hash: request.snapshot_head.root_hash.clone(),
        root_object_id: request.snapshot_head.root_object_id.clone(),
    };
    assert_eq!(result.resulting_head, expected_head);
    assert_eq!(result.resulting_epoch, fence_epoch(8));
    assert_eq!(restored.head, expected_head);
    assert_eq!(restored.lease_epoch, fence_epoch(8));
    assert!(restored.lease_owner.is_none());
    assert_eq!(
        restored.last_transition,
        Some(LastVolumeTransition::SnapshotRestore {
            request: request.clone(),
            result: result.clone(),
        })
    );

    let (replayed, replay) = restore_snapshot(&restored, &request).unwrap();
    assert_eq!(replayed, restored);
    assert_eq!(replay, result);
}

#[test]
fn snapshot_restore_requires_the_exact_unowned_strict_predecessor() {
    let base = unowned_volume();
    let request = snapshot_restore_request(&base);

    let mut wrong_size = request.clone();
    wrong_size.expected_size_bytes += 1;
    assert_eq!(
        restore_snapshot(&base, &wrong_size),
        Err(AuthorityError::HeadConflict)
    );

    let mut wrong_head = request.clone();
    wrong_head.expected_head = head(3);
    assert_eq!(
        restore_snapshot(&base, &wrong_head),
        Err(AuthorityError::HeadConflict)
    );

    let mut wrong_epoch = request.clone();
    wrong_epoch.expected_unowned_epoch = fence_epoch(6);
    assert_eq!(
        restore_snapshot(&base, &wrong_epoch),
        Err(AuthorityError::Fenced)
    );

    let (owned, _, _) = acquired_volume();
    let owned_request = snapshot_restore_request(&owned);
    assert_eq!(
        restore_snapshot(&owned, &owned_request),
        Err(AuthorityError::OtherWriter)
    );

    let mut relaxed = base.clone();
    relaxed.durability = VolumeDurability::Relaxed;
    assert_eq!(
        restore_snapshot(&relaxed, &request),
        Err(AuthorityError::InvalidDurability)
    );
}

#[test]
fn snapshot_restore_replay_never_guesses_from_a_matching_root() {
    let base = unowned_volume();
    let request = snapshot_restore_request(&base);
    let (restored, _) = restore_snapshot(&base, &request).unwrap();

    let later_request = SnapshotRestoreRequest {
        snapshot_id: id("snapshot-2"),
        expected_unowned_epoch: restored.lease_epoch,
        expected_head: restored.head.clone(),
        snapshot_head: head(3),
        ..request.clone()
    };
    let (later, _) = restore_snapshot(&restored, &later_request).unwrap();
    assert_eq!(
        restore_snapshot(&later, &request),
        Err(AuthorityError::Fenced)
    );

    let mut reused_snapshot = later_request.clone();
    reused_snapshot.disk_id = id("disk-2");
    assert_eq!(
        restore_snapshot(&later, &reused_snapshot),
        Err(AuthorityError::Fenced)
    );

    let coincidental_head = VolumeRecord {
        head: request.snapshot_head.clone(),
        last_transition: None,
        ..base
    };
    assert_eq!(
        restore_snapshot(&coincidental_head, &request),
        Err(AuthorityError::HeadConflict)
    );
}

#[test]
fn the_same_snapshot_can_be_an_explicit_later_occurrence() {
    let base = unowned_volume();
    let first_request = snapshot_restore_request(&base);
    let (first, _) = restore_snapshot(&base, &first_request).unwrap();
    let second_request = SnapshotRestoreRequest {
        expected_unowned_epoch: first.lease_epoch,
        expected_head: first.head.clone(),
        ..first_request
    };

    let (second, result) = restore_snapshot(&first, &second_request).unwrap();
    assert_eq!(second.head.generation, generation(6));
    assert_eq!(second.lease_epoch, fence_epoch(9));
    assert_eq!(
        second.head.root_hash,
        second_request.snapshot_head.root_hash
    );
    assert_eq!(result.resulting_head, second.head);
}

#[test]
fn snapshot_restore_fences_the_pre_restore_writer_epoch() {
    let (owned, _, _) = acquired_volume();
    let publish = VolumeHeadCasRequest {
        volume_id: owned.volume_id.clone(),
        attachment_id: owned.lease_owner.clone().unwrap(),
        expected_epoch: owned.lease_epoch,
        expected_size_bytes: owned.size_bytes,
        expected_head: owned.head.clone(),
        new_head: head(5),
    };
    let release_request = ReleaseRequest {
        volume_id: owned.volume_id.clone(),
        transition_id: random_id(2),
        attachment_id: owned.lease_owner.clone().unwrap(),
        expected_epoch: owned.lease_epoch,
    };
    let (unowned, _) = release(&owned, &release_request).unwrap();
    let restore_request = snapshot_restore_request(&unowned);
    let (restored, _) = restore_snapshot(&unowned, &restore_request).unwrap();

    assert_eq!(
        compare_and_swap_head(&restored, &publish),
        Err(AuthorityError::Fenced)
    );
}

#[test]
fn snapshot_restore_rejects_generation_and_epoch_overflow() {
    let mut max_generation = unowned_volume();
    max_generation.head = head(MAX_INTEGER);
    let request = snapshot_restore_request(&max_generation);
    assert_eq!(
        restore_snapshot(&max_generation, &request),
        Err(AuthorityError::GenerationExhausted)
    );

    let mut max_epoch = unowned_volume();
    max_epoch.lease_epoch = fence_epoch(MAX_INTEGER);
    let request = snapshot_restore_request(&max_epoch);
    assert_eq!(
        restore_snapshot(&max_epoch, &request),
        Err(AuthorityError::EpochExhausted)
    );
}

#[test]
fn head_cas_binds_owner_epoch_size_and_complete_predecessor() {
    let (owned, _, _) = acquired_volume();
    let request = VolumeHeadCasRequest {
        volume_id: owned.volume_id.clone(),
        attachment_id: owned.lease_owner.clone().unwrap(),
        expected_epoch: owned.lease_epoch,
        expected_size_bytes: owned.size_bytes,
        expected_head: owned.head.clone(),
        new_head: head(5),
    };
    let (published, result) = compare_and_swap_head(&owned, &request).unwrap();
    assert_eq!(published.head, head(5));
    assert_eq!(result.resulting_head, head(5));

    assert_eq!(
        compare_and_swap_head(&published, &request),
        Err(AuthorityError::HeadConflict)
    );

    let mut wrong_owner = request.clone();
    wrong_owner.attachment_id = id("attachment-b");
    assert_eq!(
        compare_and_swap_head(&owned, &wrong_owner),
        Err(AuthorityError::Fenced)
    );

    let mut wrong_size = request.clone();
    wrong_size.expected_size_bytes += 1;
    assert_eq!(
        compare_and_swap_head(&owned, &wrong_size),
        Err(AuthorityError::HeadConflict)
    );

    let mut no_advance = request;
    no_advance.new_head = no_advance.expected_head.clone();
    assert_eq!(
        compare_and_swap_head(&owned, &no_advance),
        Err(AuthorityError::HeadConflict)
    );
}

#[test]
fn every_epoch_advancing_direct_transition_fails_at_maximum() {
    let mut unowned = unowned_volume();
    unowned.lease_epoch = fence_epoch(MAX_INTEGER);
    let acquire = NormalAcquireRequest {
        expected_unowned_epoch: unowned.lease_epoch,
        ..acquire_request(1)
    };
    assert_eq!(
        normal_acquire(&unowned, &acquire, time(10_000)),
        Err(AuthorityError::EpochExhausted)
    );

    let delete = BeginDeleteRequest {
        delete_id: id("delete-max"),
        disk_id: id("disk-1"),
        volume_id: unowned.volume_id.clone(),
        expected_unowned_epoch: unowned.lease_epoch,
        expected_head: unowned.head.clone(),
    };
    assert_eq!(
        begin_delete(&unowned, &delete),
        Err(AuthorityError::EpochExhausted)
    );

    let request = NormalAcquireRequest {
        expected_unowned_epoch: fence_epoch(MAX_INTEGER - 1),
        ..acquire_request(2)
    };
    let result = NormalAcquireResult {
        volume_id: request.volume_id.clone(),
        transition_id: request.transition_id.clone(),
        attachment_id: request.attachment_id.clone(),
        resulting_epoch: fence_epoch(MAX_INTEGER),
        resulting_head: head(4),
        lease_expires_at: time(15_000),
    };
    let owned = VolumeRecord {
        volume_id: request.volume_id.clone(),
        size_bytes: 4 * 1024 * 1024,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        head: result.resulting_head.clone(),
        lease_owner: Some(request.attachment_id.clone()),
        lease_epoch: result.resulting_epoch,
        lease_expires_at: Some(result.lease_expires_at),
        last_transition: Some(LastVolumeTransition::NormalAcquire {
            request: request.clone(),
            result,
        }),
    };
    validate_volume_record(&owned).unwrap();
    assert_eq!(
        release(
            &owned,
            &ReleaseRequest {
                volume_id: owned.volume_id.clone(),
                transition_id: random_id(3),
                attachment_id: request.attachment_id,
                expected_epoch: owned.lease_epoch,
            },
        ),
        Err(AuthorityError::EpochExhausted)
    );
}

#[test]
fn projection_contains_only_direct_transition_coordinates() {
    let (owned, request, _) = acquired_volume();
    let projection = project_volume_record(&owned).unwrap();
    assert_eq!(projection.last_transition_kind, Some("normal_acquire"));
    assert_eq!(
        projection.last_transition_id,
        Some(request.transition_id.to_string())
    );
    assert_eq!(
        projection.transition_placement_epoch,
        Some(request.placement_epoch)
    );
    assert_eq!(
        projection.transition_lease_duration_ms,
        Some(request.lease_duration_ms)
    );

    let binding = VolumeOwnerBinding {
        volume_id: owned.volume_id.clone(),
        owner_node_id: id("node-a"),
        attachment_id: owned.lease_owner.clone().unwrap(),
        attachment_epoch: owned.lease_epoch,
    };
    validate_volume_owner_binding(&binding, &owned).unwrap();

    let mut wrong = binding;
    wrong.attachment_epoch = fence_epoch(1);
    assert_eq!(
        validate_volume_owner_binding(&wrong, &owned),
        Err(AuthorityError::BackendUnknown)
    );

    let base = unowned_volume();
    let request = snapshot_restore_request(&base);
    let (restored, _) = restore_snapshot(&base, &request).unwrap();
    let projection = project_volume_record(&restored).unwrap();
    assert_eq!(projection.last_transition_kind, Some("snapshot_restore"));
    assert_eq!(
        projection.last_transition_id,
        Some(request.snapshot_id.to_string())
    );
    assert_eq!(projection.transition_placement_epoch, None);
    assert_eq!(projection.transition_lease_duration_ms, None);
}

#[test]
fn retired_transition_json_shapes_are_rejected() {
    let (owned, _, _) = acquired_volume();
    let mut value = serde_json::to_value(&owned).unwrap();
    value["last_transition"] = serde_json::json!({
        "kind": "takeover",
        "authorization_id": "authorization-1"
    });
    assert!(serde_json::from_value::<VolumeRecord>(value).is_err());

    let (owned, _, _) = acquired_volume();
    let mut value = serde_json::to_value(&owned).unwrap();
    value["last_transition"]["source"] = serde_json::json!({
        "kind": "lifecycle",
        "operation_id": "operation-1",
        "request_fingerprint":
            "sha256:0000000000000000000000000000000000000000000000000000000000000001"
    });
    assert!(serde_json::from_value::<VolumeRecord>(value).is_err());
}
