use cats_api::object_write_gateway::ObjectWriteCredentialReference;
use cats_api::runtime_lifecycle::{
    DiskRole, PlacementIdentity, RuntimeVolumeConfig, RuntimeVolumeGuestBinding,
};
use cats_api::runtime_lifecycle_volume::{
    LifecycleCommandStartVolumeGrantReceipt, LifecycleRenewLeaseRequest, LifecycleRenewLeaseResult,
    LifecycleServingAcquire, LifecycleStartVolumeGrantAuthority, LifecycleVolumeCommandScope,
};
use cats_api::runtime_reconciliation::WireU64;
use cats_storage::authority::*;
use cats_storage::lifecycle_volume::command_start_volume_grant_receipt_digest_from_closed_receipt;

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

fn object_write_credential(value: u8) -> ObjectWriteCredentialReference {
    ObjectWriteCredentialReference {
        credential_id: id(&format!("object-write-credential-{value}")),
        public_key_spki_sha256: Sha256Digest::from_bytes([value; 32]),
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
        placement_epoch: epoch(3),
        lease_duration_ms: 5_000,
    }
}

fn acquired_volume() -> VolumeRecord {
    normal_acquire(&unowned_volume(), &acquire_request(1), time(10_000))
        .unwrap()
        .0
}

fn authorized_serving_attachment() -> (AuthorizedServingAttachment, VolumeRecord) {
    let transition_source = VolumeTransitionSource::Lifecycle {
        operation_id: id("operation-start-1"),
        request_fingerprint: Sha256Digest::from_bytes([17; 32]),
    };
    let request = acquire_request(1);
    let (record, _) = normal_acquire_with_source(
        &unowned_volume(),
        &transition_source,
        &request,
        time(10_000),
    )
    .unwrap();
    let LastVolumeTransition::NormalAcquire {
        source,
        request,
        result,
    } = record.last_transition.clone().unwrap()
    else {
        unreachable!("fixture is a normal acquire")
    };
    let grant = LifecycleCommandStartVolumeGrantReceipt {
        scope: LifecycleVolumeCommandScope {
            operation_id: id("operation-start-1"),
            request_fingerprint: Sha256Digest::from_bytes([17; 32]),
            cat_id: id("cat-1"),
            node_id: id("node-1"),
            placement_identity: PlacementIdentity {
                node_id: id("node-1"),
                placement_epoch: request.placement_epoch,
            },
        },
        grant_sequence: WireU64::new(0).unwrap(),
        volume: RuntimeVolumeConfig {
            volume_id: record.volume_id.clone(),
            disk_id: id("disk-root"),
            disk_role: DiskRole::Root,
            size_bytes: record.size_bytes,
            durability: record.durability,
            guest_device_serial: id("root-boot"),
            guest_device_slot: 0,
            guest_binding: RuntimeVolumeGuestBinding::RootBoot,
        },
        authority: LifecycleStartVolumeGrantAuthority::NormalAcquire { request, result },
    };
    let digest = command_start_volume_grant_receipt_digest_from_closed_receipt(&grant).unwrap();
    let attachment = authorized_serving_attachment_from_start_volume_grant(
        &grant,
        &digest,
        Some(object_write_credential(1)),
    )
    .unwrap();
    assert_eq!(attachment.transition_source, source);
    (attachment, record)
}

#[cfg(feature = "proposed-node-residue-reclamation")]
fn residue_lineage(local: u64, remote: u64) -> ResidueDataDirectoryLineage {
    let acquired = acquired_volume();
    let Some(LastVolumeTransition::NormalAcquire {
        request, result, ..
    }) = acquired.last_transition
    else {
        unreachable!("fixture is a normal acquire")
    };
    let acquisition = AuthorizedServingAcquire::Normal { request, result };
    ResidueDataDirectoryLineage {
        workspace_id: id("workspace-1"),
        cat_id: id("cat-1"),
        disk_id: id("disk-1"),
        disk_kind: DiskKind::Root,
        volume_id: id("volume-1"),
        attachment_id: id("attachment-old"),
        attachment_epoch: fence_epoch(8),
        acquire_origin: AcquireOrigin::Normal {
            transition_id: random_id(1),
        },
        node_id: id("node-old"),
        desired_revision: revision(11),
        spec_digest: Sha256Digest::from_bytes([11; 32]),
        placement: cats_api::runtime_reconciliation::AssignedPlacement {
            kind: cats_api::runtime_reconciliation::AssignedKind::Assigned,
            node_id: id("node-old"),
            placement_epoch: epoch(3),
        },
        placement_epoch: epoch(3),
        acquisition_digest: residue_acquisition_digest(&acquisition).unwrap(),
        acquisition,
        local_durable_generation: generation(local),
        remote_durable_generation: generation(remote),
        remote_head: head(remote),
        pending_pack_count: WireU64::new(local.saturating_sub(remote)).unwrap(),
        fenced: true,
    }
}

#[test]
fn authorized_serving_input_binds_identity_receipt_and_exact_authority_record() {
    let (attachment, record) = authorized_serving_attachment();
    validate_authorized_serving_attachment(&attachment).unwrap();
    validate_authorized_serving_record(&record, &attachment, Some(attachment.lease_expires_at))
        .unwrap();

    let mut wrong_origin = attachment.clone();
    wrong_origin.identity.acquire_origin = AcquireOrigin::Normal {
        transition_id: random_id(99),
    };
    assert_eq!(
        validate_authorized_serving_attachment(&wrong_origin),
        Err(AuthorityError::BackendUnknown)
    );

    let mut wrong_grant_expiry = attachment.clone();
    wrong_grant_expiry.lease_expires_at = UnixMillis::new(1).unwrap();
    assert_eq!(
        validate_authorized_serving_attachment(&wrong_grant_expiry),
        Err(AuthorityError::BackendUnknown)
    );

    // The exact owner may publish past the frozen attachment head, so a
    // strictly newer generation is the accepted successor; only an
    // equal-generation divergence stays unknown state.
    let mut published_head = record.clone();
    published_head.head = head(9);
    assert_eq!(
        validate_authorized_serving_record(
            &published_head,
            &attachment,
            Some(attachment.lease_expires_at)
        ),
        Ok(())
    );
    let mut wrong_head = record.clone();
    wrong_head.head.root_hash =
        Some(Sha256Digest::new(format!("sha256:{:064x}", 0xdead_beef_u64)).unwrap());
    assert_eq!(
        validate_authorized_serving_record(
            &wrong_head,
            &attachment,
            Some(attachment.lease_expires_at)
        ),
        Err(AuthorityError::BackendUnknown)
    );
}

#[test]
fn authorized_serving_renewal_retains_original_acquire_and_binds_current_grant() {
    let (initial, initial_record) = authorized_serving_attachment();
    let initial_grant = initial.current_lease.grant.as_ref();
    let AuthorizedServingAcquire::Normal {
        request: acquire_request,
        result: acquire_result,
    } = &initial.acquire
    else {
        unreachable!()
    };
    // The latest lease was renewed while the Root was still blank. Root
    // provisioning may then advance that exact owner/epoch before blockd is
    // launched, so the serving carrier is allowed to project the later head
    // without rewriting the immutable renewal result.
    let renewed_head = head(4);
    let renew_result = LifecycleRenewLeaseResult {
        volume_id: initial.identity.volume_id.clone(),
        attachment_id: initial.identity.attachment_id.clone(),
        epoch: initial.identity.attachment_epoch,
        resulting_head: renewed_head.clone(),
        lease_expires_at: time(20_000),
    };
    let renew_grant = LifecycleCommandStartVolumeGrantReceipt {
        scope: initial_grant.scope.clone(),
        grant_sequence: WireU64::new(1).unwrap(),
        volume: initial_grant.volume.clone(),
        authority: LifecycleStartVolumeGrantAuthority::RenewSameNode {
            expected_source: initial.transition_source.clone(),
            serving_acquire: Box::new(LifecycleServingAcquire::Normal {
                request: acquire_request.clone(),
                result: acquire_result.clone(),
            }),
            request: LifecycleRenewLeaseRequest {
                volume_id: initial.identity.volume_id.clone(),
                attachment_id: initial.identity.attachment_id.clone(),
                expected_epoch: initial.identity.attachment_epoch,
                lease_duration_ms: WireU64::new(5_000).unwrap(),
            },
            result: renew_result.clone(),
        },
    };
    let renew_digest =
        command_start_volume_grant_receipt_digest_from_closed_receipt(&renew_grant).unwrap();
    let mut renewed = authorized_serving_attachment_from_start_volume_grant(
        &renew_grant,
        &renew_digest,
        initial.object_write_credential.clone(),
    )
    .unwrap();
    renewed.head = head(5);

    assert_eq!(renewed.acquire, initial.acquire);
    assert_eq!(renewed.initial_head(), &head(4));
    assert_eq!(renewed.head, head(5));
    assert_eq!(renewed.lease_expires_at, time(20_000));
    assert_eq!(renewed.lease_duration_ms(), 5_000);
    let AuthorizedServingAcquire::Normal {
        result: retained_original,
        ..
    } = &renewed.acquire
    else {
        unreachable!()
    };
    assert_eq!(retained_original.lease_expires_at, time(15_000));

    let mut renewed_record = initial_record.clone();
    renewed_record.head = renewed.head.clone();
    renewed_record.lease_expires_at = Some(renewed.lease_expires_at);
    validate_authorized_serving_attachment(&renewed).unwrap();
    validate_authorized_serving_record(&renewed_record, &renewed, Some(renewed.lease_expires_at))
        .unwrap();

    let mut changed_original = renewed.clone();
    let AuthorizedServingAcquire::Normal { result, .. } = &mut changed_original.acquire else {
        unreachable!()
    };
    result.lease_expires_at = time(20_000);
    assert_eq!(
        validate_authorized_serving_attachment(&changed_original),
        Err(AuthorityError::BackendUnknown)
    );

    let mut changed_digest = renewed.clone();
    changed_digest.current_lease.grant_receipt_digest = Sha256Digest::from_bytes([99; 32]);
    assert_eq!(
        validate_authorized_serving_attachment(&changed_digest),
        Err(AuthorityError::BackendUnknown)
    );

    let mut changed_sequence = renewed.clone();
    changed_sequence.current_lease.grant.grant_sequence = WireU64::new(0).unwrap();
    assert_eq!(
        validate_authorized_serving_attachment(&changed_sequence),
        Err(AuthorityError::BackendUnknown)
    );

    let mut changed_result = renewed.clone();
    let LifecycleStartVolumeGrantAuthority::RenewSameNode { result, .. } =
        &mut changed_result.current_lease.grant.authority
    else {
        unreachable!()
    };
    result.resulting_head = head(6);
    assert_eq!(
        validate_authorized_serving_attachment(&changed_result),
        Err(AuthorityError::BackendUnknown)
    );

    let mut divergent_same_generation = renewed.clone();
    divergent_same_generation.head = renewed_head.clone();
    divergent_same_generation.head.root_hash = Some(Sha256Digest::from_bytes([0x5a; 32]));
    assert_eq!(
        validate_authorized_serving_attachment(&divergent_same_generation),
        Err(AuthorityError::BackendUnknown)
    );

    let mut rolled_back = renewed.clone();
    rolled_back.head = head(3);
    assert_eq!(
        validate_authorized_serving_attachment(&rolled_back),
        Err(AuthorityError::BackendUnknown)
    );

    let mut stale_record = renewed_record.clone();
    stale_record.head = renewed_head;
    assert_eq!(
        validate_authorized_serving_record(&stale_record, &renewed, None),
        Err(AuthorityError::BackendUnknown)
    );

    renewed_record.lease_expires_at = Some(time(19_999));
    assert_eq!(
        validate_authorized_serving_record(&renewed_record, &renewed, None),
        Err(AuthorityError::BackendUnknown)
    );
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

fn host_fence_basis(event: &HostFenceEvent) -> DisposableDeleteIsolationBasis {
    DisposableDeleteIsolationBasis::HostFenceEvent {
        event_id: event.event_id.clone(),
        interrupted_operation_id: id("operation-interrupted-1"),
        host_lost_result_digest: Sha256Digest::from_bytes([14; 32]),
    }
}

fn lifecycle_strong_stop_basis() -> DisposableDeleteIsolationBasis {
    DisposableDeleteIsolationBasis::LifecycleStrongStop {
        node_id: id("node-old"),
        agent_session_epoch: epoch(8),
        strong_stop_operation_id: id("operation-delete-1"),
        strong_stop_receipt_digest: Sha256Digest::from_bytes([15; 32]),
        execution_absence_proof_digest: Sha256Digest::from_bytes([16; 32]),
        inventory_attestation_digest: Sha256Digest::from_bytes([17; 32]),
    }
}

fn takeover_authorization(volume: &VolumeRecord) -> AuthorizationRecord {
    AuthorizationRecord {
        authorization: VolumeAuthorization::Takeover(VolumeTakeoverAuthorization {
            authorization_id: id("takeover-auth-1"),
            operation_id: id("operation-takeover-1"),
            request_fingerprint: Sha256Digest::from_bytes([12; 32]),
            authorized_node_id: id("node-new"),
            host_fence_event_id: id("fence-event-1"),
            interrupted_operation_id: id("operation-interrupted-1"),
            host_lost_result_digest: Sha256Digest::from_bytes([14; 32]),
            disk_id: id("disk-1"),
            volume_id: volume.volume_id.clone(),
            cat_id: id("cat-1"),
            expected_attachment_id: volume.lease_owner.clone().unwrap(),
            expected_epoch: volume.lease_epoch,
            expected_head: volume.head.clone(),
            new_attachment_id: id("attachment-new"),
            new_placement_epoch: epoch(4),
            lease_duration_ms: 6_000,
            not_after: time(30_000),
        }),
        state: AuthorizationState::Unconsumed,
    }
}

fn authorized_takeover_attachment() -> (AuthorizedServingAttachment, VolumeRecord) {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization_record = takeover_authorization(&owned);
    let (record, consumed, result) = consume_takeover(
        &owned,
        &event,
        &authorization_record,
        &id("takeover-auth-1"),
        time(20_000),
    )
    .unwrap();
    let VolumeAuthorization::Takeover(authorization) = consumed.authorization else {
        unreachable!()
    };
    let AuthorizationState::Consumed(receipt) = consumed.state else {
        unreachable!()
    };
    let AuthorizationConsumedReceipt::Takeover(receipt) = *receipt else {
        unreachable!()
    };
    (
        AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: record.volume_id.clone(),
                attachment_id: result.attachment_id,
                attachment_epoch: result.resulting_epoch,
                acquire_origin: AcquireOrigin::Takeover {
                    authorization_id: authorization.authorization_id.clone(),
                },
                node_id: authorization.authorized_node_id.clone(),
                placement_epoch: authorization.new_placement_epoch,
            },
            transition_source: VolumeTransitionSource::Lifecycle {
                operation_id: authorization.operation_id.clone(),
                request_fingerprint: authorization.request_fingerprint.clone(),
            },
            object_write_credential: Some(object_write_credential(2)),
            size_bytes: record.size_bytes,
            durability: record.durability,
            head: record.head.clone(),
            lease_expires_at: result.lease_expires_at,
            acquire: AuthorizedServingAcquire::Takeover {
                authorization: Box::new(authorization),
                receipt,
            },
            current_lease: authorized_serving_attachment().0.current_lease,
        },
        record,
    )
}

#[test]
fn authorized_takeover_requires_a_real_command_start_grant() {
    let (attachment, record) = authorized_takeover_attachment();
    assert_eq!(
        validate_authorized_serving_attachment(&attachment),
        Err(AuthorityError::BackendUnknown)
    );
    assert_eq!(
        validate_authorized_serving_record(&record, &attachment, None),
        Err(AuthorityError::BackendUnknown)
    );
}

fn disposable_authorization(
    volume: &VolumeRecord,
    basis: DisposableDeleteIsolationBasis,
) -> AuthorizationRecord {
    let authorized_node_id = match &basis {
        DisposableDeleteIsolationBasis::LifecycleStrongStop { node_id, .. } => node_id.clone(),
        DisposableDeleteIsolationBasis::HostFenceEvent { .. } => id("node-old"),
    };
    AuthorizationRecord {
        authorization: VolumeAuthorization::DisposableRootDelete(
            DisposableRootDeleteAuthorization {
                authorization_id: id("delete-auth-1"),
                operation_id: id("operation-delete-1"),
                request_fingerprint: Sha256Digest::from_bytes([13; 32]),
                authorized_node_id,
                delete_id: id("delete-1"),
                disk_id: id("disk-1"),
                volume_id: volume.volume_id.clone(),
                cat_id: id("cat-1"),
                placement_epoch: epoch(3),
                expected_attachment_id: volume.lease_owner.clone().unwrap(),
                expected_epoch: volume.lease_epoch,
                expected_head: volume.head.clone(),
                disposition: DisposableRootDisposition::DiscardWithCat,
                persistent_dispositions_digest: Sha256Digest::from_bytes([18; 32]),
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
    let authorization = disposable_authorization(&owned, host_fence_basis(&event));
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
        Some(LastVolumeTransition::Takeover {
            authorization_id, ..
        })
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
fn consumed_takeover_replays_exact_authorization() {
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
    let (unchanged, same_row, replay) = consume_takeover(
        &taken_over,
        &active,
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
fn unconsumed_takeover_rejects_expiry_and_wrong_binding() {
    let owned = acquired_volume();
    let authorization = takeover_authorization(&owned);
    let event = host_fence_event(HostFenceEventState::Active);
    assert_eq!(
        consume_takeover(
            &owned,
            &event,
            &authorization,
            &id("takeover-auth-1"),
            time(30_001),
        ),
        Err(AuthorityError::InvalidAuthorization)
    );

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
    let authorization = disposable_authorization(&owned, host_fence_basis(&event));
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

    let replay = consume_disposable_root_delete(
        &deleting,
        Some(&event),
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
fn disposable_strong_stop_and_host_fence_bases_cannot_be_confused() {
    let owned = acquired_volume();
    let stopped = disposable_authorization(&owned, lifecycle_strong_stop_basis());
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

    let mut mismatched = stopped.clone();
    let VolumeAuthorization::DisposableRootDelete(authorization) = &mut mismatched.authorization
    else {
        unreachable!()
    };
    let DisposableDeleteIsolationBasis::LifecycleStrongStop {
        strong_stop_operation_id,
        ..
    } = &mut authorization.isolation_basis
    else {
        unreachable!()
    };
    *strong_stop_operation_id = id("operation-other");
    assert_eq!(
        consume_disposable_root_delete(
            &owned,
            None,
            &mismatched,
            &id("delete-auth-1"),
            time(20_000),
        ),
        Err(AuthorityError::BackendUnknown)
    );
    assert!(matches!(stopped.state, AuthorizationState::Unconsumed));
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
    let disposable = disposable_authorization(&owned, host_fence_basis(&event));
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
    let authorization = disposable_authorization(&owned, host_fence_basis(&event));
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
#[cfg(feature = "proposed-node-residue-reclamation")]
fn residue_reclaim_accepts_only_exact_direct_ordinary_release() {
    let owned = acquired_volume();
    let (released, _) = release(
        &owned,
        &ReleaseRequest {
            volume_id: owned.volume_id.clone(),
            transition_id: random_id(90),
            attachment_id: id("attachment-old"),
            expected_epoch: fence_epoch(8),
        },
    )
    .unwrap();
    let lineage = residue_lineage(4, 4);
    let expected = RuntimeResidueAuthorityOutcome::Reclaimable {
        proof: Box::new(ResidueReclaimProof::OrdinaryRelease {
            current_volume: Box::new(released.clone()),
        }),
    };
    assert_eq!(
        classify_residue_reclaim_authority(&lineage, Some(&released), None, None).unwrap(),
        expected
    );
    // Response loss and Agent restart repeat the same pure decision.
    assert_eq!(
        classify_residue_reclaim_authority(&lineage, Some(&released), None, None).unwrap(),
        expected
    );

    let mut stale = lineage.clone();
    stale.attachment_epoch = fence_epoch(7);
    assert!(matches!(
        classify_residue_reclaim_authority(&stale, Some(&released), None, None).unwrap(),
        RuntimeResidueAuthorityOutcome::Retained { .. }
    ));

    let mut successor_request = acquire_request(2);
    successor_request.expected_unowned_epoch = released.lease_epoch;
    successor_request.attachment_id = id("attachment-new");
    let (successor, _) = normal_acquire(&released, &successor_request, time(20_000)).unwrap();
    assert_eq!(
        classify_residue_reclaim_authority(&lineage, Some(&successor), None, None).unwrap(),
        RuntimeResidueAuthorityOutcome::Retained {
            reason: ResidueAuthorityRetentionReason::CurrentOrNewerOwner,
        }
    );
}

#[test]
#[cfg(feature = "proposed-node-residue-reclamation")]
fn residue_reclaim_accepts_exact_normal_delete_completion_only_at_r_equals_l() {
    let owned = acquired_volume();
    let (released, _) = release(
        &owned,
        &ReleaseRequest {
            volume_id: owned.volume_id.clone(),
            transition_id: random_id(90),
            attachment_id: id("attachment-old"),
            expected_epoch: fence_epoch(8),
        },
    )
    .unwrap();
    let request = BeginDeleteRequest {
        delete_id: id("delete-1"),
        disk_id: id("disk-1"),
        volume_id: released.volume_id.clone(),
        expected_unowned_epoch: released.lease_epoch,
        expected_head: released.head.clone(),
    };
    let deleting = begin_delete(&released, &request).unwrap().0;
    let completion = complete_normal_delete(&deleting, time(40_000)).unwrap();
    let lineage = residue_lineage(4, 4);
    assert!(matches!(
        classify_residue_reclaim_authority(&lineage, None, Some(&completion), None).unwrap(),
        RuntimeResidueAuthorityOutcome::Reclaimable { proof }
            if matches!(proof.as_ref(), ResidueReclaimProof::NormalDeleteCompletion { .. })
    ));

    let local_tail = residue_lineage(5, 4);
    assert_eq!(
        classify_residue_reclaim_authority(&local_tail, None, Some(&completion), None).unwrap(),
        RuntimeResidueAuthorityOutcome::Retained {
            reason: ResidueAuthorityRetentionReason::UniqueLocalTail,
        }
    );
}

#[test]
#[cfg(feature = "proposed-node-residue-reclamation")]
fn residue_reclaim_accepts_exact_disposable_root_consumed_completion() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = disposable_authorization(&owned, host_fence_basis(&event));
    let (deleting, consumed, _) = consume_disposable_root_delete(
        &owned,
        Some(&event),
        &authorization,
        &id("delete-auth-1"),
        time(20_000),
    )
    .unwrap();
    let completion = complete_disposable_root_delete(&deleting, &consumed, time(40_000)).unwrap();
    let mut lineage = residue_lineage(6, 4);
    lineage.desired_revision = revision(13);
    assert!(matches!(
        classify_residue_reclaim_authority(&lineage, None, Some(&completion), Some(&consumed),)
            .unwrap(),
        RuntimeResidueAuthorityOutcome::Reclaimable { proof }
            if matches!(proof.as_ref(), ResidueReclaimProof::DisposableRootDeleteCompletion { .. })
    ));
    assert_eq!(
        classify_residue_reclaim_authority(&lineage, None, Some(&completion), None).unwrap(),
        RuntimeResidueAuthorityOutcome::Retained {
            reason: ResidueAuthorityRetentionReason::DeleteIncomplete,
        }
    );

    let mut persistent = lineage.clone();
    persistent.disk_kind = DiskKind::Persistent;
    assert_eq!(
        classify_residue_reclaim_authority(&persistent, None, Some(&completion), Some(&consumed),)
            .unwrap(),
        RuntimeResidueAuthorityOutcome::Retained {
            reason: ResidueAuthorityRetentionReason::UnsupportedDiskKind,
        }
    );

    let mut wrong_delete = completion.clone();
    let DeleteCompletionReceipt::DisposableRoot { delete_id, .. } = &mut wrong_delete else {
        unreachable!("fixture is a disposable-root completion")
    };
    *delete_id = id("delete-other");
    assert!(matches!(
        classify_residue_reclaim_authority(&lineage, None, Some(&wrong_delete), Some(&consumed),)
            .unwrap(),
        RuntimeResidueAuthorityOutcome::Retained { .. }
    ));

    let mut before_consumption = completion;
    let DeleteCompletionReceipt::DisposableRoot { completed_at, .. } = &mut before_consumption
    else {
        unreachable!("fixture is a disposable-root completion")
    };
    *completed_at = time(19_999);
    assert!(matches!(
        classify_residue_reclaim_authority(
            &lineage,
            None,
            Some(&before_consumption),
            Some(&consumed),
        )
        .unwrap(),
        RuntimeResidueAuthorityOutcome::Retained { .. }
    ));
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
    let disposable = disposable_authorization(&owned, host_fence_basis(&event));
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

#[test]
fn data_plane_head_cas_compares_owner_epoch_and_complete_head() {
    let owned = acquired_volume();
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
    assert_eq!(published.lease_owner, owned.lease_owner);
    assert_eq!(published.lease_epoch, owned.lease_epoch);
    assert_eq!(published.lease_expires_at, owned.lease_expires_at);
    assert_eq!(published.last_transition, owned.last_transition);
    assert_eq!(result.resulting_head, head(5));

    let mut wrong_owner = request.clone();
    wrong_owner.attachment_id = id("attachment-other");
    assert_eq!(
        compare_and_swap_head(&owned, &wrong_owner),
        Err(AuthorityError::Fenced)
    );

    let mut wrong_epoch = request.clone();
    wrong_epoch.expected_epoch = fence_epoch(request.expected_epoch.get() - 1);
    assert_eq!(
        compare_and_swap_head(&owned, &wrong_epoch),
        Err(AuthorityError::Fenced)
    );

    let mut same_generation_different_root = request;
    same_generation_different_root.expected_head = RemoteHead {
        generation: owned.head.generation,
        root_hash: Some(Sha256Digest::new(format!("sha256:{:064x}", 99)).unwrap()),
        root_object_id: Some(AsciiText::new("roots/99").unwrap()),
    };
    assert_eq!(
        compare_and_swap_head(&owned, &same_generation_different_root),
        Err(AuthorityError::HeadConflict)
    );

    let mut wrong_size = same_generation_different_root;
    wrong_size.expected_head = owned.head.clone();
    wrong_size.expected_size_bytes = owned.size_bytes + 1;
    assert_eq!(
        compare_and_swap_head(&owned, &wrong_size),
        Err(AuthorityError::HeadConflict)
    );
    assert_eq!(owned, acquired_volume());
}

#[test]
fn volume_projection_is_derived_from_the_validated_authority_record() {
    let owned = acquired_volume();
    let projection = project_volume_record(&owned).unwrap();
    assert_eq!(projection.volume_id, owned.volume_id.as_str());
    assert_eq!(projection.size_bytes, owned.size_bytes);
    assert_eq!(projection.durability, "strict");
    assert_eq!(projection.admin_state, "active");
    assert_eq!(projection.head_generation, owned.head.generation);
    assert_eq!(projection.lease_owner.as_deref(), Some("attachment-old"));
    assert_eq!(projection.lease_epoch, owned.lease_epoch);
    assert_eq!(projection.last_transition_kind, Some("normal_acquire"));
    assert_eq!(projection.transition_source_kind, Some("independent"));
    assert_eq!(projection.transition_operation_id, None);
    assert_eq!(projection.transition_request_fingerprint, None);
    assert_eq!(projection.transition_placement_epoch, Some(epoch(3)));
    assert_eq!(projection.transition_lease_duration_ms, Some(5_000));
}

#[test]
fn evidence_bundle_accepts_takeover_response_loss_and_closed_later_states() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    let (taken_over, consumed, _) = consume_takeover(
        &owned,
        &event,
        &authorization,
        &id("takeover-auth-1"),
        time(20_000),
    )
    .unwrap();
    validate_volume_transition_evidence_bundle(&consumed, Some(&taken_over), None, None).unwrap();

    let (renewed, _) = renew_lease(
        &taken_over,
        &RenewLeaseRequest {
            volume_id: taken_over.volume_id.clone(),
            attachment_id: id("attachment-new"),
            expected_epoch: taken_over.lease_epoch,
            lease_duration_ms: 5_000,
        },
        time(25_000),
    )
    .unwrap();
    let (published, _) = compare_and_swap_head(
        &renewed,
        &VolumeHeadCasRequest {
            volume_id: renewed.volume_id.clone(),
            attachment_id: id("attachment-new"),
            expected_epoch: renewed.lease_epoch,
            expected_size_bytes: renewed.size_bytes,
            expected_head: renewed.head.clone(),
            new_head: head(5),
        },
    )
    .unwrap();
    validate_volume_transition_evidence_bundle(&consumed, Some(&published), None, None).unwrap();

    let (released, _) = release(
        &published,
        &ReleaseRequest {
            volume_id: published.volume_id.clone(),
            transition_id: random_id(91),
            attachment_id: id("attachment-new"),
            expected_epoch: published.lease_epoch,
        },
    )
    .unwrap();
    validate_volume_transition_evidence_bundle(&consumed, Some(&released), None, None).unwrap();
}

#[test]
fn evidence_bundle_requires_the_exact_direct_successor_authorization() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let primary = takeover_authorization(&owned);
    let (first_volume, consumed_primary, _) = consume_takeover(
        &owned,
        &event,
        &primary,
        &id("takeover-auth-1"),
        time(20_000),
    )
    .unwrap();

    let mut successor = takeover_authorization(&first_volume);
    let VolumeAuthorization::Takeover(payload) = &mut successor.authorization else {
        unreachable!()
    };
    payload.authorization_id = id("takeover-auth-2");
    payload.expected_attachment_id = id("attachment-new");
    payload.new_attachment_id = id("attachment-newer");
    payload.authorized_node_id = id("node-newer");
    let (second_volume, consumed_successor, _) = consume_takeover(
        &first_volume,
        &event,
        &successor,
        &id("takeover-auth-2"),
        time(21_000),
    )
    .unwrap();

    validate_volume_transition_evidence_bundle(
        &consumed_primary,
        Some(&second_volume),
        None,
        Some(&consumed_successor),
    )
    .unwrap();
    assert_eq!(
        validate_volume_transition_evidence_bundle(
            &consumed_primary,
            Some(&second_volume),
            None,
            None,
        ),
        Err(AuthorityError::BackendUnknown)
    );

    let mut regressed = consumed_successor.clone();
    let AuthorizationState::Consumed(receipt) = &mut regressed.state else {
        unreachable!()
    };
    let AuthorizationConsumedReceipt::Takeover(receipt) = receipt.as_mut() else {
        unreachable!()
    };
    receipt.resulting_head = empty_head();
    assert_eq!(
        validate_volume_transition_evidence_bundle(
            &consumed_primary,
            Some(&second_volume),
            None,
            Some(&regressed),
        ),
        Err(AuthorityError::BackendUnknown)
    );

    let mut wrong_volume = consumed_successor;
    let VolumeAuthorization::Takeover(payload) = &mut wrong_volume.authorization else {
        unreachable!()
    };
    payload.volume_id = id("volume-other");
    assert_eq!(
        validate_volume_transition_evidence_bundle(
            &consumed_primary,
            Some(&second_volume),
            None,
            Some(&wrong_volume),
        ),
        Err(AuthorityError::BackendUnknown)
    );
}

#[test]
fn evidence_bundle_closes_disposable_delete_completion_and_rejects_split_state() {
    let owned = acquired_volume();
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = disposable_authorization(&owned, host_fence_basis(&event));
    let (deleting, consumed, _) = consume_disposable_root_delete(
        &owned,
        Some(&event),
        &authorization,
        &id("delete-auth-1"),
        time(20_000),
    )
    .unwrap();
    let completion = complete_disposable_root_delete(&deleting, &consumed, time(40_000)).unwrap();
    validate_volume_transition_evidence_bundle(&consumed, None, Some(&completion), None).unwrap();
    assert_eq!(
        validate_volume_transition_evidence_bundle(
            &consumed,
            Some(&deleting),
            Some(&completion),
            None,
        ),
        Err(AuthorityError::BackendUnknown)
    );

    let mut time_regressed = completion.clone();
    let DeleteCompletionReceipt::DisposableRoot { completed_at, .. } = &mut time_regressed else {
        unreachable!()
    };
    *completed_at = time(19_999);
    assert_eq!(
        validate_volume_transition_evidence_bundle(&consumed, None, Some(&time_regressed), None,),
        Err(AuthorityError::BackendUnknown)
    );

    let mut corrupt = completion;
    let DeleteCompletionReceipt::DisposableRoot { deleting_epoch, .. } = &mut corrupt else {
        unreachable!()
    };
    *deleting_epoch = fence_epoch(deleting_epoch.get() + 1);
    assert_eq!(
        validate_volume_transition_evidence_bundle(&consumed, None, Some(&corrupt), None),
        Err(AuthorityError::BackendUnknown)
    );
}
