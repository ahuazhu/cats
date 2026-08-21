use cats_api::runtime_lifecycle::{
    DiskRole, PlacementIdentity, RuntimeVolumeConfig, RuntimeVolumeGuestBinding,
};
use cats_api::runtime_lifecycle_volume::{
    LifecycleCommandStartVolumeGrantReceipt, LifecyclePersistentGuestFilesystemState,
    LifecyclePersistentInitializationBinding, LifecyclePersistentInitializationCommitRequest,
    LifecyclePersistentInitializationFlushDrainReceipt,
    LifecyclePersistentInitializationGuestProbe, LifecyclePersistentInitializationState,
    LifecycleRenewLeaseRequest, LifecycleRenewLeaseResult, LifecycleServingAcquire,
    LifecycleStartVolumeGrantAuthority, LifecycleStoredStartVolumeGrant,
    LifecycleVolumeCommandScope as WireLifecycleVolumeCommandScope,
    LifecycleVolumeDurabilityProof as WireLifecycleVolumeDurabilityProof,
    LifecycleVolumeTarget as WireLifecycleVolumeTarget,
};
use cats_api::runtime_reconciliation::{
    BeginDeleteRequest, LastVolumeTransition, ReleaseRequest, WireU64,
};
use cats_storage::authority::{
    begin_delete_with_source, complete_normal_delete, normal_acquire, normal_acquire_with_source,
    release_with_source, renew_lease, AsciiText, AuthorizationRecord, AuthorizationState,
    DisposableDeleteIsolationBasis, DisposableRootDeleteAuthorization, DisposableRootDisposition,
    Epoch, FenceEpoch, Generation, Id, NormalAcquireRequest, RandomId128, RemoteHead, Sha256Digest,
    UnixMillis, VolumeAdminState, VolumeAuthorization, VolumeDurability, VolumeOwnerBinding,
    VolumeRecord, VolumeTransitionSource,
};
use cats_storage::lifecycle_volume::{
    begin_delete_disposable_root, command_cold_already_unowned_receipt_digest,
    command_cold_already_unowned_receipt_digest_from_closed_receipt,
    command_delete_already_unowned_receipt_digest,
    command_delete_already_unowned_receipt_digest_from_closed_receipt,
    command_delete_completion_receipt_digest,
    command_disposable_authorization_consumed_receipt_digest,
    command_disposable_authorization_consumed_receipt_digest_from_delete_completion,
    command_normal_release_receipt_digest, command_normal_release_receipt_digest_for_deleting_root,
    command_normal_release_receipt_digest_from_closed_receipt,
    command_normal_release_receipt_digest_from_delete_completion,
    command_start_volume_grant_receipt_digest, commit_persistent_initialization,
    complete_delete_disposable_root, decode_canonical_command_delete_completion_receipt,
    decode_canonical_command_disposable_authorization_consumed_receipt,
    decode_canonical_command_normal_release_receipt,
    decode_canonical_command_start_volume_grant_receipt, encode_command_delete_completion_receipt,
    encode_command_disposable_authorization_consumed_receipt,
    encode_command_normal_release_receipt, encode_command_start_volume_grant_receipt,
    inspect_persistent_initialization, persistent_delete_dispositions_digest,
    release_cold_volume_set, release_delete_normal_volume_set,
    release_delete_persistent_volume_set, validate_cold_volume_release_receipts,
    validate_delete_disposable_root_completion, AlreadyUnownedProvenance, ColdCommandVolumeSet,
    CommandAlreadyUnownedReceipt, CommandBoundDisposableRootAuthorization,
    CommandDeleteCompletionReceipt, CommandNormalReleaseInput, CommandNormalReleaseReceipt,
    CommandRootDeleteAuthorityReceipt, CommandVolumeDurabilityProof, DefaultRootDiscardDisposition,
    DeleteCommandVolumeSet, DeleteDisposableRootInput, LifecycleVolumeCommandScope,
    LifecycleVolumeDispositionInput, LifecycleVolumeError, LifecycleVolumeTarget,
};

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

fn head(value: u64) -> RemoteHead {
    RemoteHead {
        generation: generation(value),
        root_hash: Some(Sha256Digest::new(format!("sha256:{:064x}", value.max(1))).unwrap()),
        root_object_id: Some(AsciiText::new(format!("roots/{value}")).unwrap()),
    }
}

fn blank_head() -> RemoteHead {
    RemoteHead {
        generation: generation(0),
        root_hash: None,
        root_object_id: None,
    }
}

fn scope(operation: &str) -> LifecycleVolumeCommandScope {
    LifecycleVolumeCommandScope {
        operation_id: id(operation),
        request_fingerprint: Sha256Digest::new(format!(
            "sha256:{:064x}",
            operation
                .bytes()
                .fold(0_u64, |sum, byte| sum + u64::from(byte))
        ))
        .unwrap(),
        cat_id: id("cat-1"),
        node_id: id("node-1"),
        placement_identity: PlacementIdentity {
            node_id: id("node-1"),
            placement_epoch: epoch(3),
        },
    }
}

fn wire_scope(command_scope: &LifecycleVolumeCommandScope) -> WireLifecycleVolumeCommandScope {
    WireLifecycleVolumeCommandScope {
        operation_id: command_scope.operation_id.clone(),
        request_fingerprint: command_scope.request_fingerprint.clone(),
        cat_id: command_scope.cat_id.clone(),
        node_id: command_scope.node_id.clone(),
        placement_identity: command_scope.placement_identity.clone(),
    }
}

fn root_runtime_volume(volume_id: &str, disk_id: &str) -> RuntimeVolumeConfig {
    RuntimeVolumeConfig {
        volume_id: id(volume_id),
        disk_id: id(disk_id),
        disk_role: DiskRole::Root,
        size_bytes: 4 * 1024 * 1024,
        durability: VolumeDurability::Relaxed,
        guest_device_serial: id("root-boot"),
        guest_device_slot: 0,
        guest_binding: RuntimeVolumeGuestBinding::RootBoot,
    }
}

fn persistent_runtime_volume(volume_id: &str, disk_id: &str) -> RuntimeVolumeConfig {
    RuntimeVolumeConfig {
        volume_id: id(volume_id),
        disk_id: id(disk_id),
        disk_role: DiskRole::Persistent,
        size_bytes: 4 * 1024 * 1024,
        durability: VolumeDurability::Relaxed,
        guest_device_serial: id("persistent-data"),
        guest_device_slot: 1,
        guest_binding: RuntimeVolumeGuestBinding::PersistentExt4 {
            filesystem_uuid: random_id(700),
            mount_path: AsciiText::new("/data").unwrap(),
        },
    }
}

fn owned_volume(
    volume_id: &str,
    attachment_id: &str,
    remote_generation: u64,
    acquire_transition: u128,
) -> VolumeRecord {
    let unowned = VolumeRecord {
        volume_id: id(volume_id),
        size_bytes: 4 * 1024 * 1024,
        durability: VolumeDurability::Relaxed,
        admin_state: VolumeAdminState::Active,
        head: head(remote_generation),
        lease_owner: None,
        lease_epoch: fence_epoch(7),
        lease_expires_at: None,
        last_transition: None,
    };
    normal_acquire(
        &unowned,
        &NormalAcquireRequest {
            volume_id: unowned.volume_id.clone(),
            transition_id: random_id(acquire_transition),
            attachment_id: id(attachment_id),
            expected_unowned_epoch: unowned.lease_epoch,
            placement_epoch: epoch(3),
            lease_duration_ms: 5_000,
        },
        time(10_000),
    )
    .unwrap()
    .0
}

fn pristine_volume(volume_id: &str, remote_generation: u64) -> VolumeRecord {
    VolumeRecord {
        volume_id: id(volume_id),
        size_bytes: 4 * 1024 * 1024,
        durability: VolumeDurability::Relaxed,
        admin_state: VolumeAdminState::Active,
        head: head(remote_generation),
        lease_owner: None,
        lease_epoch: fence_epoch(7),
        lease_expires_at: None,
        last_transition: None,
    }
}

fn target(disk_id: &str, disk_role: DiskRole, volume: &VolumeRecord) -> LifecycleVolumeTarget {
    LifecycleVolumeTarget {
        disk_id: id(disk_id),
        disk_role,
        volume_id: volume.volume_id.clone(),
        attachment_id: volume.lease_owner.clone().unwrap(),
        attachment_epoch: volume.lease_epoch,
    }
}

fn proof(
    command_scope: &LifecycleVolumeCommandScope,
    volume: &LifecycleVolumeTarget,
    local: u64,
    remote: u64,
) -> CommandVolumeDurabilityProof {
    CommandVolumeDurabilityProof {
        scope: command_scope.clone(),
        volume: volume.clone(),
        remote_head: head(remote),
        local_durable_generation: generation(local),
        remote_durable_generation: generation(remote),
        pending_pack_count: WireU64::new(local.saturating_sub(remote)).unwrap(),
    }
}

fn release_input(
    durability: CommandVolumeDurabilityProof,
    transition: u128,
) -> CommandNormalReleaseInput {
    CommandNormalReleaseInput {
        durability,
        transition_id: random_id(transition),
    }
}

fn owned_release(input: CommandNormalReleaseInput) -> LifecycleVolumeDispositionInput {
    LifecycleVolumeDispositionInput::OwnedRelease { release: input }
}

fn disposable_authorization(
    command_scope: &LifecycleVolumeCommandScope,
    root: &LifecycleVolumeTarget,
    remote_head: &RemoteHead,
) -> CommandBoundDisposableRootAuthorization {
    CommandBoundDisposableRootAuthorization {
        scope: command_scope.clone(),
        authorization: AuthorizationRecord {
            authorization: VolumeAuthorization::DisposableRootDelete(
                DisposableRootDeleteAuthorization {
                    authorization_id: id("root-delete-authorization-1"),
                    operation_id: command_scope.operation_id.clone(),
                    request_fingerprint: command_scope.request_fingerprint.clone(),
                    authorized_node_id: id("node-1"),
                    delete_id: id("delete-1"),
                    disk_id: root.disk_id.clone(),
                    volume_id: root.volume_id.clone(),
                    cat_id: command_scope.cat_id.clone(),
                    placement_epoch: epoch(3),
                    expected_attachment_id: root.attachment_id.clone(),
                    expected_epoch: root.attachment_epoch,
                    expected_head: remote_head.clone(),
                    disposition: DisposableRootDisposition::DiscardWithCat,
                    persistent_dispositions_digest: Sha256Digest::from_bytes([14; 32]),
                    isolation_basis: DisposableDeleteIsolationBasis::LifecycleStrongStop {
                        node_id: id("node-1"),
                        agent_session_epoch: epoch(8),
                        strong_stop_operation_id: command_scope.operation_id.clone(),
                        strong_stop_receipt_digest: Sha256Digest::from_bytes([15; 32]),
                        execution_absence_proof_digest: Sha256Digest::from_bytes([16; 32]),
                        inventory_attestation_digest: Sha256Digest::from_bytes([17; 32]),
                    },
                    not_after: time(30_000),
                },
            ),
            state: AuthorizationState::Unconsumed,
        },
    }
}

fn delete_input(
    command_scope: &LifecycleVolumeCommandScope,
    root: &LifecycleVolumeTarget,
    persistent: &LifecycleVolumeTarget,
    current_persistent: &VolumeRecord,
    persistent_local: u64,
    persistent_remote: u64,
) -> DeleteDisposableRootInput {
    let root_durability = proof(command_scope, root, 5, 4);
    let mut input = DeleteDisposableRootInput {
        command: DeleteCommandVolumeSet {
            scope: command_scope.clone(),
            root_disposition: DefaultRootDiscardDisposition {
                root: root.identity(),
                delete_id: id("delete-1"),
            },
            persistent_volumes: vec![persistent.identity()],
        },
        persistent_volumes: vec![owned_release(release_input(
            proof(
                command_scope,
                persistent,
                persistent_local,
                persistent_remote,
            ),
            31,
        ))],
        root_authorization: disposable_authorization(
            command_scope,
            root,
            &root_durability.remote_head,
        ),
        root_durability,
    };
    if let Ok((released, receipts)) = release_delete_persistent_volume_set(
        &input.command,
        std::slice::from_ref(current_persistent),
        &input.persistent_volumes,
    ) {
        let digest = persistent_delete_dispositions_digest(&input.command, &released, &receipts)
            .expect("valid fixture Persistent dispositions");
        let VolumeAuthorization::DisposableRootDelete(authorization) =
            &mut input.root_authorization.authorization.authorization
        else {
            unreachable!()
        };
        authorization.persistent_dispositions_digest = digest;
    }
    input
}

fn normal_root_delete_receipts(
    command_scope: &LifecycleVolumeCommandScope,
) -> (
    DeleteCommandVolumeSet,
    VolumeRecord,
    VolumeRecord,
    CommandNormalReleaseReceipt,
    CommandDeleteCompletionReceipt,
) {
    let root = owned_volume("normal-root-volume", "normal-root-attachment", 6, 71);
    let root_target = target("normal-root-disk", DiskRole::Root, &root);
    let command = DeleteCommandVolumeSet {
        scope: command_scope.clone(),
        root_disposition: DefaultRootDiscardDisposition {
            root: root_target.identity(),
            delete_id: id("normal-delete-1"),
        },
        persistent_volumes: Vec::new(),
    };
    let request = ReleaseRequest {
        volume_id: root_target.volume_id.clone(),
        transition_id: random_id(72),
        attachment_id: root_target.attachment_id.clone(),
        expected_epoch: root_target.attachment_epoch,
    };
    let source = VolumeTransitionSource::Lifecycle {
        operation_id: command_scope.operation_id.clone(),
        request_fingerprint: command_scope.request_fingerprint.clone(),
    };
    let (released, result) = release_with_source(&root, &source, &request).unwrap();
    let release_receipt = CommandNormalReleaseReceipt {
        durability: proof(command_scope, &root_target, 6, 6),
        request,
        result,
    };
    command_normal_release_receipt_digest(command_scope, &root_target, &released, &release_receipt)
        .unwrap();

    let begin_request = BeginDeleteRequest {
        delete_id: command.root_disposition.delete_id.clone(),
        disk_id: root_target.disk_id.clone(),
        volume_id: root_target.volume_id.clone(),
        expected_unowned_epoch: released.lease_epoch,
        expected_head: released.head.clone(),
    };
    let (deleting, _) = begin_delete_with_source(&released, &source, &begin_request).unwrap();
    let completion = complete_normal_delete(&deleting, time(50_000)).unwrap();
    let command_completion = CommandDeleteCompletionReceipt {
        command: command.clone(),
        root_authority: CommandRootDeleteAuthorityReceipt::NormalRelease(release_receipt.clone()),
        completion,
    };
    (
        command,
        released,
        deleting,
        release_receipt,
        command_completion,
    )
}

#[test]
fn cold_releases_the_complete_ordered_root_and_persistent_set_at_exact_r_equals_l() {
    let root = owned_volume("a-root-volume", "root-attachment", 4, 1);
    let persistent = owned_volume("b-persistent-volume", "persistent-attachment", 7, 2);
    let command_scope = scope("cold-operation-1");
    let root_target = target("root-disk", DiskRole::Root, &root);
    let persistent_target = target("persistent-disk", DiskRole::Persistent, &persistent);
    let command = ColdCommandVolumeSet {
        scope: command_scope.clone(),
        volumes: vec![root_target.identity(), persistent_target.identity()],
    };
    let inputs = vec![
        owned_release(release_input(proof(&command_scope, &root_target, 4, 4), 11)),
        owned_release(release_input(
            proof(&command_scope, &persistent_target, 7, 7),
            12,
        )),
    ];

    let (released, receipts) =
        release_cold_volume_set(&command, &[root, persistent], &inputs).unwrap();
    assert!(released.iter().all(|volume| volume.lease_owner.is_none()));
    assert_eq!(receipts.dispositions.len(), 2);
    validate_cold_volume_release_receipts(&command, &released, &receipts).unwrap();

    // Exact replay returns the same authority markers and receipts.
    let (replayed, replayed_receipts) =
        release_cold_volume_set(&command, &released, &inputs).unwrap();
    assert_eq!(replayed, released);
    assert_eq!(replayed_receipts, receipts);
}

#[test]
fn cold_rejects_an_incomplete_or_reordered_volume_set() {
    let root = owned_volume("a-root-volume", "root-attachment", 4, 1);
    let persistent = owned_volume("b-persistent-volume", "persistent-attachment", 7, 2);
    let command_scope = scope("cold-operation-1");
    let root_target = target("root-disk", DiskRole::Root, &root);
    let persistent_target = target("persistent-disk", DiskRole::Persistent, &persistent);
    let command = ColdCommandVolumeSet {
        scope: command_scope.clone(),
        volumes: vec![root_target.identity(), persistent_target.identity()],
    };
    let root_input = owned_release(release_input(proof(&command_scope, &root_target, 4, 4), 11));
    let persistent_input = owned_release(release_input(
        proof(&command_scope, &persistent_target, 7, 7),
        12,
    ));

    assert_eq!(
        release_cold_volume_set(
            &command,
            std::slice::from_ref(&root),
            std::slice::from_ref(&root_input),
        ),
        Err(LifecycleVolumeError::VolumeSetMismatch)
    );
    assert_eq!(
        release_cold_volume_set(
            &command,
            &[root, persistent],
            &[persistent_input, root_input],
        ),
        Err(LifecycleVolumeError::VolumeSetMismatch)
    );
}

#[test]
fn cold_never_uses_root_discard_when_root_has_a_unique_local_tail() {
    let root = owned_volume("root-volume", "root-attachment", 4, 1);
    let before = root.clone();
    let command_scope = scope("cold-operation-1");
    let root_target = target("root-disk", DiskRole::Root, &root);
    let command = ColdCommandVolumeSet {
        scope: command_scope.clone(),
        volumes: vec![root_target.identity()],
    };
    let inputs = vec![owned_release(release_input(
        proof(&command_scope, &root_target, 5, 4),
        11,
    ))];

    assert_eq!(
        release_cold_volume_set(&command, std::slice::from_ref(&root), &inputs),
        Err(LifecycleVolumeError::DurabilityNotConverged)
    );
    assert_eq!(root, before);
}

#[test]
fn normal_delete_releases_the_complete_root_and_persistent_set_before_delete() {
    let root = owned_volume("root-volume", "root-attachment", 4, 1);
    let persistent = owned_volume("persistent-volume", "persistent-attachment", 7, 2);
    let command_scope = scope("normal-delete-operation-1");
    let root_target = target("root-disk", DiskRole::Root, &root);
    let persistent_target = target("persistent-disk", DiskRole::Persistent, &persistent);
    let command = DeleteCommandVolumeSet {
        scope: command_scope.clone(),
        root_disposition: DefaultRootDiscardDisposition {
            root: root_target.identity(),
            delete_id: id("delete-1"),
        },
        persistent_volumes: vec![persistent_target.identity()],
    };
    let inputs = vec![
        owned_release(release_input(proof(&command_scope, &root_target, 4, 4), 11)),
        owned_release(release_input(
            proof(&command_scope, &persistent_target, 7, 7),
            12,
        )),
    ];
    let (released, receipts) =
        release_delete_normal_volume_set(&command, &[root, persistent], &inputs).unwrap();
    assert_eq!(released.len(), 2);
    assert_eq!(receipts.len(), 2);
    for ((target, record), receipt) in [root_target, persistent_target]
        .iter()
        .zip(&released)
        .zip(&receipts)
    {
        let cats_storage::lifecycle_volume::CommandVolumeDispositionReceipt::NormallyReleased {
            receipt,
        } = receipt
        else {
            panic!("owned fixture must release")
        };
        command_normal_release_receipt_digest(&command_scope, target, record, receipt).unwrap();
    }
}

#[test]
fn persistent_tail_blocks_delete_before_any_root_discard_mutation() {
    let root = owned_volume("root-volume", "root-attachment", 4, 1);
    let persistent = owned_volume("persistent-volume", "persistent-attachment", 7, 2);
    let command_scope = scope("delete-operation-1");
    let root_target = target("root-disk", DiskRole::Root, &root);
    let persistent_target = target("persistent-disk", DiskRole::Persistent, &persistent);
    let input = delete_input(
        &command_scope,
        &root_target,
        &persistent_target,
        &persistent,
        8,
        7,
    );
    let root_before = root.clone();
    let authorization_before = input.root_authorization.clone();

    assert_eq!(
        begin_delete_disposable_root(
            std::slice::from_ref(&persistent),
            &root,
            None,
            &input,
            time(20_000),
        ),
        Err(LifecycleVolumeError::DurabilityNotConverged)
    );
    assert_eq!(root, root_before);
    assert_eq!(input.root_authorization, authorization_before);
    assert!(matches!(root.admin_state, VolumeAdminState::Active));
    assert!(matches!(
        input.root_authorization.authorization.state,
        AuthorizationState::Unconsumed
    ));
}

#[test]
fn delete_discards_only_the_default_root_after_persistent_release_and_waits_completion() {
    let root = owned_volume("root-volume", "root-attachment", 4, 1);
    let persistent = owned_volume("persistent-volume", "persistent-attachment", 7, 2);
    let command_scope = scope("delete-operation-1");
    let root_target = target("root-disk", DiskRole::Root, &root);
    let persistent_target = target("persistent-disk", DiskRole::Persistent, &persistent);
    let input = delete_input(
        &command_scope,
        &root_target,
        &persistent_target,
        &persistent,
        7,
        7,
    );

    let begun = begin_delete_disposable_root(
        std::slice::from_ref(&persistent),
        &root,
        None,
        &input,
        time(20_000),
    )
    .unwrap();
    assert_eq!(begun.persistent_volumes[0].lease_owner, None);
    assert!(matches!(
        begun.root_volume.admin_state,
        VolumeAdminState::Deleting { ref delete_id } if delete_id == &id("delete-1")
    ));
    assert_eq!(begun.root_volume.lease_owner, None);
    assert!(matches!(
        begun.root_authorization.authorization.state,
        AuthorizationState::Consumed(_)
    ));

    let completed = complete_delete_disposable_root(
        &input.command,
        &begun.persistent_volumes,
        &begun.root_volume,
        &begun.root_authorization,
        &begun.receipt,
        time(40_000),
    )
    .unwrap();
    validate_delete_disposable_root_completion(
        &input.command,
        &begun.persistent_volumes,
        &completed,
    )
    .unwrap();
}

#[test]
fn command_release_rejects_wrong_operation_head_attachment_and_epoch() {
    let root = owned_volume("root-volume", "root-attachment", 4, 1);
    let command_scope = scope("cold-operation-1");
    let root_target = target("root-disk", DiskRole::Root, &root);
    let base_command = ColdCommandVolumeSet {
        scope: command_scope.clone(),
        volumes: vec![root_target.identity()],
    };

    let mut wrong_operation = release_input(proof(&command_scope, &root_target, 4, 4), 11);
    wrong_operation.durability.scope.operation_id = id("cold-operation-other");
    assert_eq!(
        release_cold_volume_set(
            &base_command,
            std::slice::from_ref(&root),
            &[owned_release(wrong_operation)],
        ),
        Err(LifecycleVolumeError::CommandScopeMismatch)
    );

    let mut wrong_head = release_input(proof(&command_scope, &root_target, 4, 4), 11);
    wrong_head.durability.remote_head = head(3);
    wrong_head.durability.remote_durable_generation = generation(3);
    wrong_head.durability.local_durable_generation = generation(3);
    assert_eq!(
        release_cold_volume_set(
            &base_command,
            std::slice::from_ref(&root),
            &[owned_release(wrong_head)],
        ),
        Err(LifecycleVolumeError::Authority(
            cats_storage::authority::AuthorityError::HeadConflict
        ))
    );

    for wrong_target in [
        LifecycleVolumeTarget {
            attachment_id: id("attachment-other"),
            ..root_target.clone()
        },
        LifecycleVolumeTarget {
            attachment_epoch: fence_epoch(7),
            ..root_target.clone()
        },
    ] {
        let command = ColdCommandVolumeSet {
            scope: command_scope.clone(),
            volumes: vec![wrong_target.identity()],
        };
        let input = release_input(proof(&command_scope, &wrong_target, 4, 4), 11);
        assert_eq!(
            release_cold_volume_set(
                &command,
                std::slice::from_ref(&root),
                &[owned_release(input)],
            ),
            Err(LifecycleVolumeError::Authority(
                cats_storage::authority::AuthorityError::Fenced
            ))
        );
    }
}

#[test]
fn root_discard_rejects_wrong_operation_head_attachment_and_epoch() {
    let root = owned_volume("root-volume", "root-attachment", 4, 1);
    let persistent = owned_volume("persistent-volume", "persistent-attachment", 7, 2);
    let command_scope = scope("delete-operation-1");
    let root_target = target("root-disk", DiskRole::Root, &root);
    let persistent_target = target("persistent-disk", DiskRole::Persistent, &persistent);
    let base = delete_input(
        &command_scope,
        &root_target,
        &persistent_target,
        &persistent,
        7,
        7,
    );

    let mut wrong_operation = base.clone();
    wrong_operation.root_authorization.scope.operation_id = id("delete-operation-other");
    assert_eq!(
        begin_delete_disposable_root(
            std::slice::from_ref(&persistent),
            &root,
            None,
            &wrong_operation,
            time(20_000),
        ),
        Err(LifecycleVolumeError::CommandScopeMismatch)
    );

    let mut wrong_head = base.clone();
    wrong_head.root_durability.remote_head = head(3);
    wrong_head.root_durability.remote_durable_generation = generation(3);
    assert_eq!(
        begin_delete_disposable_root(
            std::slice::from_ref(&persistent),
            &root,
            None,
            &wrong_head,
            time(20_000),
        ),
        Err(LifecycleVolumeError::Authority(
            cats_storage::authority::AuthorityError::HeadConflict
        ))
    );

    let mut wrong_attachment = base.clone();
    let VolumeAuthorization::DisposableRootDelete(authorization) = &mut wrong_attachment
        .root_authorization
        .authorization
        .authorization
    else {
        unreachable!()
    };
    authorization.expected_attachment_id = id("attachment-other");
    assert_eq!(
        begin_delete_disposable_root(
            std::slice::from_ref(&persistent),
            &root,
            None,
            &wrong_attachment,
            time(20_000),
        ),
        Err(LifecycleVolumeError::Authority(
            cats_storage::authority::AuthorityError::InvalidAuthorization
        ))
    );

    let mut wrong_epoch = base;
    let VolumeAuthorization::DisposableRootDelete(authorization) =
        &mut wrong_epoch.root_authorization.authorization.authorization
    else {
        unreachable!()
    };
    authorization.expected_epoch = fence_epoch(7);
    assert_eq!(
        begin_delete_disposable_root(
            std::slice::from_ref(&persistent),
            &root,
            None,
            &wrong_epoch,
            time(20_000),
        ),
        Err(LifecycleVolumeError::Authority(
            cats_storage::authority::AuthorityError::InvalidAuthorization
        ))
    );
}

#[test]
fn start_grant_digest_is_stable_validated_and_operation_scoped() {
    let command_scope = scope("start-operation-1");
    let volume_config = root_runtime_volume("start-root-volume", "start-root-disk");
    let unowned = VolumeRecord {
        volume_id: volume_config.volume_id.clone(),
        size_bytes: volume_config.size_bytes,
        durability: volume_config.durability,
        admin_state: VolumeAdminState::Active,
        head: head(3),
        lease_owner: None,
        lease_epoch: fence_epoch(7),
        lease_expires_at: None,
        last_transition: None,
    };
    let request = NormalAcquireRequest {
        volume_id: volume_config.volume_id.clone(),
        transition_id: random_id(101),
        attachment_id: id("start-root-attachment"),
        expected_unowned_epoch: unowned.lease_epoch,
        placement_epoch: command_scope.placement_identity.placement_epoch,
        lease_duration_ms: 5_000,
    };
    let (acquired, result) = normal_acquire_with_source(
        &unowned,
        &VolumeTransitionSource::Lifecycle {
            operation_id: command_scope.operation_id.clone(),
            request_fingerprint: command_scope.request_fingerprint.clone(),
        },
        &request,
        time(10_000),
    )
    .unwrap();
    let receipt = LifecycleCommandStartVolumeGrantReceipt {
        scope: wire_scope(&command_scope),
        grant_sequence: WireU64::new(0).unwrap(),
        volume: volume_config.clone(),
        authority: LifecycleStartVolumeGrantAuthority::NormalAcquire { request, result },
    };
    let encoded = encode_command_start_volume_grant_receipt(
        &command_scope,
        WireU64::new(0).unwrap(),
        &volume_config,
        &acquired,
        &receipt,
    )
    .unwrap();
    assert_eq!(
        command_start_volume_grant_receipt_digest(
            &command_scope,
            WireU64::new(0).unwrap(),
            &volume_config,
            &acquired,
            &receipt,
        )
        .unwrap(),
        encoded.receipt_digest
    );
    assert_eq!(
        decode_canonical_command_start_volume_grant_receipt(&encoded.canonical_receipt_bytes)
            .unwrap(),
        receipt
    );

    let mut malformed = receipt.clone();
    malformed.volume.disk_id = id("wrong-disk");
    assert_eq!(
        command_start_volume_grant_receipt_digest(
            &command_scope,
            WireU64::new(0).unwrap(),
            &volume_config,
            &acquired,
            &malformed,
        ),
        Err(LifecycleVolumeError::ReceiptMismatch)
    );

    let other_scope = scope("start-operation-2");
    let mut other_receipt = receipt.clone();
    other_receipt.scope = wire_scope(&other_scope);
    let mut other_acquired = acquired.clone();
    let Some(LastVolumeTransition::NormalAcquire { source, .. }) =
        &mut other_acquired.last_transition
    else {
        unreachable!()
    };
    *source = VolumeTransitionSource::Lifecycle {
        operation_id: other_scope.operation_id.clone(),
        request_fingerprint: other_scope.request_fingerprint.clone(),
    };
    assert_ne!(
        command_start_volume_grant_receipt_digest(
            &other_scope,
            WireU64::new(0).unwrap(),
            &volume_config,
            &other_acquired,
            &other_receipt,
        )
        .unwrap(),
        encoded.receipt_digest
    );
    assert_eq!(
        command_start_volume_grant_receipt_digest(
            &command_scope,
            WireU64::new(0).unwrap(),
            &volume_config,
            &acquired,
            &other_receipt,
        ),
        Err(LifecycleVolumeError::CommandScopeMismatch)
    );

    assert_eq!(
        encoded.receipt_digest.as_str(),
        "sha256:8d13843f444482836c0c4c2e4f6bffb3b18b563384df14172ce753ff5e1d3114"
    );
}

#[test]
fn start_renew_grant_binds_prior_lifecycle_source_and_exact_expiry() {
    let acquire_scope = scope("start-acquire-operation");
    let renew_scope = scope("start-renew-operation");
    let volume_config = root_runtime_volume("renew-root-volume", "renew-root-disk");
    let unowned = VolumeRecord {
        volume_id: volume_config.volume_id.clone(),
        size_bytes: volume_config.size_bytes,
        durability: volume_config.durability,
        admin_state: VolumeAdminState::Active,
        head: head(5),
        lease_owner: None,
        lease_epoch: fence_epoch(9),
        lease_expires_at: None,
        last_transition: None,
    };
    let expected_source = VolumeTransitionSource::Lifecycle {
        operation_id: acquire_scope.operation_id.clone(),
        request_fingerprint: acquire_scope.request_fingerprint.clone(),
    };
    let (acquired, acquire_result) = normal_acquire_with_source(
        &unowned,
        &expected_source,
        &NormalAcquireRequest {
            volume_id: volume_config.volume_id.clone(),
            transition_id: random_id(111),
            attachment_id: id("renew-root-attachment"),
            expected_unowned_epoch: unowned.lease_epoch,
            placement_epoch: acquire_scope.placement_identity.placement_epoch,
            lease_duration_ms: 5_000,
        },
        time(10_000),
    )
    .unwrap();
    let request = LifecycleRenewLeaseRequest {
        volume_id: volume_config.volume_id.clone(),
        attachment_id: acquired.lease_owner.clone().unwrap(),
        expected_epoch: acquired.lease_epoch,
        lease_duration_ms: WireU64::new(7_000).unwrap(),
    };
    let (renewed, authority_result) = renew_lease(
        &acquired,
        &cats_storage::authority::RenewLeaseRequest {
            volume_id: request.volume_id.clone(),
            attachment_id: request.attachment_id.clone(),
            expected_epoch: request.expected_epoch,
            lease_duration_ms: request.lease_duration_ms.get(),
        },
        time(20_000),
    )
    .unwrap();
    let receipt = LifecycleCommandStartVolumeGrantReceipt {
        scope: wire_scope(&renew_scope),
        grant_sequence: WireU64::new(4).unwrap(),
        volume: volume_config.clone(),
        authority: LifecycleStartVolumeGrantAuthority::RenewSameNode {
            expected_source: expected_source.clone(),
            serving_acquire: Box::new(LifecycleServingAcquire::Normal {
                request: match &acquired.last_transition {
                    Some(LastVolumeTransition::NormalAcquire { request, .. }) => request.clone(),
                    _ => unreachable!(),
                },
                result: acquire_result,
            }),
            request,
            result: LifecycleRenewLeaseResult {
                volume_id: authority_result.volume_id,
                attachment_id: authority_result.attachment_id,
                epoch: authority_result.epoch,
                resulting_head: renewed.head.clone(),
                lease_expires_at: authority_result.lease_expires_at,
            },
        },
    };
    command_start_volume_grant_receipt_digest(
        &renew_scope,
        WireU64::new(4).unwrap(),
        &volume_config,
        &renewed,
        &receipt,
    )
    .unwrap();

    let mut wrong_expiry = receipt.clone();
    let LifecycleStartVolumeGrantAuthority::RenewSameNode { result, .. } =
        &mut wrong_expiry.authority
    else {
        unreachable!()
    };
    result.lease_expires_at = time(result.lease_expires_at.get() + 1);
    assert_eq!(
        command_start_volume_grant_receipt_digest(
            &renew_scope,
            WireU64::new(4).unwrap(),
            &volume_config,
            &renewed,
            &wrong_expiry,
        ),
        Err(LifecycleVolumeError::ReceiptMismatch)
    );

    let mut independent = receipt;
    let LifecycleStartVolumeGrantAuthority::RenewSameNode {
        expected_source, ..
    } = &mut independent.authority
    else {
        unreachable!()
    };
    *expected_source = VolumeTransitionSource::Independent;
    assert_eq!(
        command_start_volume_grant_receipt_digest(
            &renew_scope,
            WireU64::new(4).unwrap(),
            &volume_config,
            &renewed,
            &independent,
        ),
        Err(LifecycleVolumeError::ReceiptMismatch)
    );
}

#[test]
fn normal_release_digest_is_stable_validated_and_operation_scoped() {
    let command_scope = scope("normal-delete-operation-1");
    let (command, released, deleting, receipt, completion) =
        normal_root_delete_receipts(&command_scope);
    let digest = command_normal_release_receipt_digest(
        &command_scope,
        &receipt.durability.volume,
        &released,
        &receipt,
    )
    .unwrap();
    assert_eq!(
        command_normal_release_receipt_digest(
            &command_scope,
            &receipt.durability.volume,
            &released,
            &receipt,
        )
        .unwrap(),
        digest
    );
    assert_eq!(
        digest.as_str(),
        "sha256:71681866927a00a0737b504e1ca4a03d1d8f366d6ccd5c0904da42fc79529d30"
    );
    let encoded = encode_command_normal_release_receipt(
        &command_scope,
        &receipt.durability.volume,
        &released,
        &receipt,
    )
    .unwrap();
    assert_eq!(encoded.receipt_digest, digest);
    assert_eq!(
        decode_canonical_command_normal_release_receipt(&encoded.canonical_receipt_bytes).unwrap(),
        receipt
    );
    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&encoded.canonical_receipt_bytes);
    assert!(decode_canonical_command_normal_release_receipt(&noncanonical).is_err());
    assert_eq!(
        command_normal_release_receipt_digest_for_deleting_root(&command, &deleting, &receipt,)
            .unwrap(),
        digest
    );
    assert_eq!(
        command_normal_release_receipt_digest_from_delete_completion(&command, &completion)
            .unwrap(),
        digest
    );
    assert_eq!(
        command_normal_release_receipt_digest_from_closed_receipt(&receipt).unwrap(),
        digest
    );

    let mut malformed = receipt.clone();
    malformed.result.released_attachment_id = id("wrong-attachment");
    assert_eq!(
        command_normal_release_receipt_digest(
            &command_scope,
            &receipt.durability.volume,
            &released,
            &malformed,
        ),
        Err(LifecycleVolumeError::ReceiptMismatch)
    );

    let mut unconverged = receipt.clone();
    unconverged.durability.local_durable_generation = generation(7);
    unconverged.durability.pending_pack_count = WireU64::new(1).unwrap();
    assert_eq!(
        command_normal_release_receipt_digest(
            &command_scope,
            &receipt.durability.volume,
            &released,
            &unconverged,
        ),
        Err(LifecycleVolumeError::DurabilityNotConverged)
    );

    let other_scope = scope("normal-delete-operation-2");
    let mut other_operation_receipt = receipt.clone();
    other_operation_receipt.durability.scope = other_scope.clone();
    let mut other_released = released.clone();
    let Some(LastVolumeTransition::Release { source, .. }) = &mut other_released.last_transition
    else {
        unreachable!()
    };
    *source = VolumeTransitionSource::Lifecycle {
        operation_id: other_scope.operation_id.clone(),
        request_fingerprint: other_scope.request_fingerprint.clone(),
    };
    let other_digest = command_normal_release_receipt_digest(
        &other_scope,
        &receipt.durability.volume,
        &other_released,
        &other_operation_receipt,
    )
    .unwrap();
    assert_ne!(other_digest, digest);
    assert_eq!(
        command_normal_release_receipt_digest(
            &command_scope,
            &receipt.durability.volume,
            &released,
            &other_operation_receipt,
        ),
        Err(LifecycleVolumeError::CommandScopeMismatch)
    );
}

#[test]
fn already_unowned_digests_are_closed_stable_and_cross_command_separated() {
    let prior_scope = scope("prior-cold-operation-1");
    let (_command, released, _deleting, prior_release, _completion) =
        normal_root_delete_receipts(&prior_scope);
    let prior_digest =
        command_normal_release_receipt_digest_from_closed_receipt(&prior_release).unwrap();
    let current_scope = scope("mixed-cold-operation-1");
    let receipt = CommandAlreadyUnownedReceipt {
        scope: current_scope.clone(),
        volume: prior_release.durability.volume.identity(),
        expected_epoch: released.lease_epoch,
        expected_head: released.head.clone(),
        provenance: AlreadyUnownedProvenance::NormalRelease {
            receipt: Box::new(prior_release.clone()),
            receipt_digest: prior_digest,
        },
    };

    let cold_digest = command_cold_already_unowned_receipt_digest(
        &current_scope,
        &receipt.volume,
        &released,
        &receipt,
    )
    .unwrap();
    let delete_digest = command_delete_already_unowned_receipt_digest(
        &current_scope,
        &receipt.volume,
        &released,
        &receipt,
    )
    .unwrap();
    assert_eq!(
        command_cold_already_unowned_receipt_digest_from_closed_receipt(&receipt).unwrap(),
        cold_digest
    );
    assert_eq!(
        command_delete_already_unowned_receipt_digest_from_closed_receipt(&receipt).unwrap(),
        delete_digest
    );
    assert_ne!(cold_digest, delete_digest);
    assert_eq!(
        cold_digest.as_str(),
        "sha256:a8c0ba6d0fc4740451eba234798e8966f62e3ea1c370ae37791a74ef43c4a734"
    );
    assert_eq!(
        delete_digest.as_str(),
        "sha256:967b922e19b27ebf611a3bdb7c40df0e569fc8afda453a8e7499ce88bd077a3e"
    );

    let mut other_operation = receipt.clone();
    other_operation.scope = scope("mixed-cold-operation-2");
    let other_digest =
        command_cold_already_unowned_receipt_digest_from_closed_receipt(&other_operation).unwrap();
    assert_ne!(other_digest, cold_digest);

    let mut wrong_epoch = receipt.clone();
    wrong_epoch.expected_epoch = fence_epoch(wrong_epoch.expected_epoch.get() + 1);
    assert_eq!(
        command_cold_already_unowned_receipt_digest_from_closed_receipt(&wrong_epoch),
        Err(LifecycleVolumeError::ReceiptMismatch)
    );

    let mut wrong_head = receipt.clone();
    wrong_head.expected_head = head(wrong_head.expected_head.generation.get() + 1);
    assert_eq!(
        command_delete_already_unowned_receipt_digest_from_closed_receipt(&wrong_head),
        Err(LifecycleVolumeError::ReceiptMismatch)
    );

    let mut wrong_prior_digest = receipt.clone();
    let AlreadyUnownedProvenance::NormalRelease { receipt_digest, .. } =
        &mut wrong_prior_digest.provenance
    else {
        unreachable!()
    };
    *receipt_digest = Sha256Digest::from_bytes([0x77; 32]);
    assert_eq!(
        command_cold_already_unowned_receipt_digest_from_closed_receipt(&wrong_prior_digest),
        Err(LifecycleVolumeError::ReceiptMismatch)
    );

    let mut unconverged_prior = receipt;
    let AlreadyUnownedProvenance::NormalRelease { receipt: prior, .. } =
        &mut unconverged_prior.provenance
    else {
        unreachable!()
    };
    prior.durability.local_durable_generation =
        generation(prior.durability.local_durable_generation.get() + 1);
    assert_eq!(
        command_delete_already_unowned_receipt_digest_from_closed_receipt(&unconverged_prior),
        Err(LifecycleVolumeError::DurabilityNotConverged)
    );
}

#[test]
fn disposable_consumed_digest_is_stable_validated_and_operation_scoped() {
    let root = owned_volume("root-volume", "root-attachment", 4, 1);
    let persistent = owned_volume("persistent-volume", "persistent-attachment", 7, 2);
    let command_scope = scope("delete-operation-1");
    let root_target = target("root-disk", DiskRole::Root, &root);
    let persistent_target = target("persistent-disk", DiskRole::Persistent, &persistent);
    let input = delete_input(
        &command_scope,
        &root_target,
        &persistent_target,
        &persistent,
        7,
        7,
    );
    let begun = begin_delete_disposable_root(
        std::slice::from_ref(&persistent),
        &root,
        None,
        &input,
        time(20_000),
    )
    .unwrap();

    let persistent_digest = persistent_delete_dispositions_digest(
        &input.command,
        &begun.persistent_volumes,
        &begun.receipt.persistent_dispositions,
    )
    .unwrap();
    assert_eq!(
        persistent_digest.as_str(),
        "sha256:4d9a7c1251a9dda993b9a8351d47e2e91bd87b46e5c5d48383acc2f02534daff"
    );
    let VolumeAuthorization::DisposableRootDelete(authorization) =
        &begun.root_authorization.authorization.authorization
    else {
        unreachable!()
    };
    assert_eq!(
        authorization.persistent_dispositions_digest,
        persistent_digest
    );
    assert_eq!(
        begun.receipt.root_begin.persistent_dispositions_digest,
        persistent_digest
    );
    let mut malformed_persistent = begun.receipt.persistent_dispositions.clone();
    let cats_storage::lifecycle_volume::CommandVolumeDispositionReceipt::NormallyReleased {
        receipt,
    } = &mut malformed_persistent[0]
    else {
        unreachable!()
    };
    receipt.durability.remote_head.root_object_id = Some(AsciiText::new("roots/wrong").unwrap());
    assert!(persistent_delete_dispositions_digest(
        &input.command,
        &begun.persistent_volumes,
        &malformed_persistent,
    )
    .is_err());

    let digest = command_disposable_authorization_consumed_receipt_digest(
        &input.command,
        &begun.root_volume,
        &begun.root_authorization,
        &begun.receipt.root_begin,
    )
    .unwrap();
    assert_eq!(
        command_disposable_authorization_consumed_receipt_digest(
            &input.command,
            &begun.root_volume,
            &begun.root_authorization,
            &begun.receipt.root_begin,
        )
        .unwrap(),
        digest
    );
    assert_eq!(
        digest.as_str(),
        "sha256:7623e53b48a61f0751cdd9d5ad302646862f516ee4cb4a6e86f6975d2e7b9229"
    );
    let encoded = encode_command_disposable_authorization_consumed_receipt(
        &input.command,
        &begun.root_volume,
        &begun.root_authorization,
        &begun.receipt.root_begin,
    )
    .unwrap();
    assert_eq!(encoded.receipt_digest, digest);
    assert_eq!(
        decode_canonical_command_disposable_authorization_consumed_receipt(
            &encoded.canonical_receipt_bytes
        )
        .unwrap(),
        begun.receipt.root_begin
    );

    let mut malformed = begun.receipt.root_begin.clone();
    malformed.receipt.cat_id = id("wrong-cat");
    assert_eq!(
        command_disposable_authorization_consumed_receipt_digest(
            &input.command,
            &begun.root_volume,
            &begun.root_authorization,
            &malformed,
        ),
        Err(LifecycleVolumeError::ReceiptMismatch)
    );

    let mut wrong_persistent_set = begun.receipt.root_begin.clone();
    wrong_persistent_set.persistent_dispositions_digest = Sha256Digest::from_bytes([0x44; 32]);
    assert!(command_disposable_authorization_consumed_receipt_digest(
        &input.command,
        &begun.root_volume,
        &begun.root_authorization,
        &wrong_persistent_set,
    )
    .is_err());

    let other_scope = scope("delete-operation-2");
    let mut other_command = input.command.clone();
    other_command.scope = other_scope.clone();
    let mut other_authorization = begun.root_authorization.clone();
    other_authorization.scope = other_scope.clone();
    let VolumeAuthorization::DisposableRootDelete(other_payload) =
        &mut other_authorization.authorization.authorization
    else {
        unreachable!()
    };
    other_payload.operation_id = other_scope.operation_id.clone();
    other_payload.request_fingerprint = other_scope.request_fingerprint.clone();
    let DisposableDeleteIsolationBasis::LifecycleStrongStop {
        strong_stop_operation_id,
        ..
    } = &mut other_payload.isolation_basis
    else {
        unreachable!()
    };
    *strong_stop_operation_id = other_scope.operation_id.clone();
    let mut other_receipt = begun.receipt.root_begin.clone();
    other_receipt.command.scope = other_scope.clone();
    let mut other_root = begun.root_volume.clone();
    let Some(LastVolumeTransition::BeginDisposableDelete { source, .. }) =
        &mut other_root.last_transition
    else {
        unreachable!()
    };
    *source = VolumeTransitionSource::Lifecycle {
        operation_id: other_scope.operation_id,
        request_fingerprint: other_scope.request_fingerprint,
    };
    let other_digest = command_disposable_authorization_consumed_receipt_digest(
        &other_command,
        &other_root,
        &other_authorization,
        &other_receipt,
    )
    .unwrap();
    assert_ne!(other_digest, digest);
    assert_eq!(
        command_disposable_authorization_consumed_receipt_digest(
            &input.command,
            &begun.root_volume,
            &begun.root_authorization,
            &other_receipt,
        ),
        Err(LifecycleVolumeError::CommandScopeMismatch)
    );

    let completed = complete_delete_disposable_root(
        &input.command,
        &begun.persistent_volumes,
        &begun.root_volume,
        &begun.root_authorization,
        &begun.receipt,
        time(40_000),
    )
    .unwrap();
    let completion = CommandDeleteCompletionReceipt {
        command: input.command.clone(),
        root_authority: CommandRootDeleteAuthorityReceipt::DisposableAuthorizationConsumed(
            begun.receipt.root_begin.clone(),
        ),
        completion: completed.completion,
    };
    let completion_digest = command_delete_completion_receipt_digest(
        &input.command,
        None,
        Some(&begun.root_authorization),
        &completion,
    )
    .unwrap();
    assert_eq!(
        completion_digest.as_str(),
        "sha256:64f0b1aafd4b445d1879edc05e6de4a9f57b422f27e875f4177a8bf3cf8fb118"
    );
    assert_eq!(
        command_disposable_authorization_consumed_receipt_digest_from_delete_completion(
            &input.command,
            &begun.root_authorization,
            &completion,
        )
        .unwrap(),
        digest
    );
}

#[test]
fn persistent_delete_dispositions_digest_closes_mixed_set_and_order() {
    let command_scope = scope("mixed-persistent-delete-operation-1");
    let pristine = pristine_volume("a-pristine-persistent-volume", 3);
    let owned = owned_volume("b-owned-persistent-volume", "persistent-attachment", 7, 81);
    let pristine_identity = cats_storage::lifecycle_volume::LifecycleVolumeIdentity {
        disk_id: id("a-pristine-persistent-disk"),
        disk_role: DiskRole::Persistent,
        volume_id: pristine.volume_id.clone(),
    };
    let owned_target = target("b-owned-persistent-disk", DiskRole::Persistent, &owned);
    let command = DeleteCommandVolumeSet {
        scope: command_scope.clone(),
        root_disposition: DefaultRootDiscardDisposition {
            root: cats_storage::lifecycle_volume::LifecycleVolumeIdentity {
                disk_id: id("root-disk"),
                disk_role: DiskRole::Root,
                volume_id: id("root-volume"),
            },
            delete_id: id("mixed-delete-1"),
        },
        persistent_volumes: vec![pristine_identity.clone(), owned_target.identity()],
    };
    let inputs = vec![
        LifecycleVolumeDispositionInput::AlreadyUnowned {
            volume: pristine_identity,
            expected_epoch: pristine.lease_epoch,
            expected_head: pristine.head.clone(),
            provenance: AlreadyUnownedProvenance::Pristine,
        },
        owned_release(release_input(
            proof(&command_scope, &owned_target, 7, 7),
            82,
        )),
    ];
    let (released, receipts) =
        release_delete_persistent_volume_set(&command, &[pristine.clone(), owned], &inputs)
            .unwrap();
    let digest = persistent_delete_dispositions_digest(&command, &released, &receipts).unwrap();
    assert_eq!(
        digest.as_str(),
        "sha256:daab4746a11e6b878354c179f6d181c888ee41c9b6fdfbf92c92ce9a10ed29ac"
    );

    let mut changed_head = receipts.clone();
    let cats_storage::lifecycle_volume::CommandVolumeDispositionReceipt::AlreadyUnowned { receipt } =
        &mut changed_head[0]
    else {
        unreachable!()
    };
    receipt.expected_head = head(4);
    assert!(persistent_delete_dispositions_digest(&command, &released, &changed_head).is_err());

    assert!(
        persistent_delete_dispositions_digest(&command, &released[..1], &receipts[..1],).is_err()
    );
    assert!(persistent_delete_dispositions_digest(
        &command,
        &[released[1].clone(), released[0].clone()],
        &receipts,
    )
    .is_err());

    let mut wrong_operation = receipts;
    let cats_storage::lifecycle_volume::CommandVolumeDispositionReceipt::AlreadyUnowned { receipt } =
        &mut wrong_operation[0]
    else {
        unreachable!()
    };
    receipt.scope = scope("mixed-persistent-delete-operation-2");
    assert_eq!(
        persistent_delete_dispositions_digest(&command, &released, &wrong_operation),
        Err(LifecycleVolumeError::CommandScopeMismatch)
    );
}

#[test]
fn delete_completion_digest_retains_prior_authority_and_is_operation_scoped() {
    let command_scope = scope("normal-delete-operation-1");
    let (command, _released, _deleting, _release, receipt) =
        normal_root_delete_receipts(&command_scope);
    let digest = command_delete_completion_receipt_digest(&command, None, None, &receipt).unwrap();
    assert_eq!(
        command_delete_completion_receipt_digest(&command, None, None, &receipt).unwrap(),
        digest
    );
    assert_eq!(
        digest.as_str(),
        "sha256:32c759b4e3d3900061fad4d3dc1007c20c8d3adfaa912b29d1922223ed60b3e1"
    );
    let encoded = encode_command_delete_completion_receipt(&command, None, None, &receipt).unwrap();
    assert_eq!(encoded.receipt_digest, digest);
    assert_eq!(
        decode_canonical_command_delete_completion_receipt(&encoded.canonical_receipt_bytes)
            .unwrap(),
        receipt
    );

    assert_eq!(
        command_delete_completion_receipt_digest(
            &command,
            Some(&owned_volume("still-present", "still-owned", 1, 91)),
            None,
            &receipt,
        ),
        Err(LifecycleVolumeError::ReceiptMismatch)
    );

    let mut malformed = receipt.clone();
    let cats_api::runtime_reconciliation::DeleteCompletionReceipt::Normal { deleting_head, .. } =
        &mut malformed.completion
    else {
        unreachable!()
    };
    *deleting_head = head(5);
    assert!(command_delete_completion_receipt_digest(&command, None, None, &malformed).is_err());

    let mut malformed_authority = receipt.clone();
    let CommandRootDeleteAuthorityReceipt::NormalRelease(release) =
        &mut malformed_authority.root_authority
    else {
        unreachable!()
    };
    release.durability.pending_pack_count = WireU64::new(1).unwrap();
    assert_eq!(
        command_delete_completion_receipt_digest(&command, None, None, &malformed_authority),
        Err(LifecycleVolumeError::DurabilityNotConverged)
    );

    let other_scope = scope("normal-delete-operation-2");
    let mut other_command = command.clone();
    other_command.scope = other_scope.clone();
    let mut other_receipt = receipt.clone();
    other_receipt.command.scope = other_scope.clone();
    let CommandRootDeleteAuthorityReceipt::NormalRelease(release) =
        &mut other_receipt.root_authority
    else {
        unreachable!()
    };
    release.durability.scope = other_scope;
    let other_digest =
        command_delete_completion_receipt_digest(&other_command, None, None, &other_receipt)
            .unwrap();
    assert_ne!(other_digest, digest);
    assert_eq!(
        command_delete_completion_receipt_digest(&command, None, None, &other_receipt),
        Err(LifecycleVolumeError::CommandScopeMismatch)
    );
}

#[test]
fn persistent_initialization_is_one_way_exact_and_replays_first_timestamp() {
    let command_scope = scope("operation-persistent-initialization");
    let wire_command_scope = wire_scope(&command_scope);
    let volume = persistent_runtime_volume("volume-persistent-init", "disk-persistent-init");
    let unowned = VolumeRecord {
        volume_id: volume.volume_id.clone(),
        size_bytes: volume.size_bytes,
        durability: volume.durability,
        admin_state: VolumeAdminState::Active,
        head: blank_head(),
        lease_owner: None,
        lease_epoch: fence_epoch(0),
        lease_expires_at: None,
        last_transition: None,
    };
    let acquire_request = NormalAcquireRequest {
        volume_id: volume.volume_id.clone(),
        transition_id: random_id(701),
        attachment_id: id("attachment-persistent-init"),
        expected_unowned_epoch: unowned.lease_epoch,
        placement_epoch: command_scope.placement_identity.placement_epoch,
        lease_duration_ms: 60_000,
    };
    let (acquired, acquire_result) = normal_acquire_with_source(
        &unowned,
        &VolumeTransitionSource::Lifecycle {
            operation_id: command_scope.operation_id.clone(),
            request_fingerprint: command_scope.request_fingerprint.clone(),
        },
        &acquire_request,
        time(10_000),
    )
    .unwrap();
    let grant_receipt = LifecycleCommandStartVolumeGrantReceipt {
        scope: wire_command_scope.clone(),
        grant_sequence: WireU64::new(0).unwrap(),
        volume: volume.clone(),
        authority: LifecycleStartVolumeGrantAuthority::NormalAcquire {
            request: acquire_request,
            result: acquire_result,
        },
    };
    let grant_digest = command_start_volume_grant_receipt_digest(
        &command_scope,
        WireU64::new(0).unwrap(),
        &volume,
        &acquired,
        &grant_receipt,
    )
    .unwrap();
    let binding = LifecyclePersistentInitializationBinding {
        scope: wire_command_scope.clone(),
        runtime_config_id: id("config-persistent-init"),
        runtime_config_digest: Sha256Digest::from_bytes([71; 32]),
        volume: volume.clone(),
        start_grant: LifecycleStoredStartVolumeGrant {
            receipt: grant_receipt,
            receipt_digest: grant_digest,
        },
    };
    let owner = VolumeOwnerBinding {
        volume_id: volume.volume_id.clone(),
        owner_node_id: command_scope.node_id.clone(),
        attachment_id: id("attachment-persistent-init"),
        attachment_epoch: acquired.lease_epoch,
    };
    let initial = LifecyclePersistentInitializationState::Uninitialized {
        initialization_token: random_id(702),
        filesystem_uuid: random_id(700),
        expected_blank_head: blank_head(),
    };
    let inspected =
        inspect_persistent_initialization(&binding, &acquired, &owner, &initial).unwrap();
    assert_eq!(inspected.initialization, initial);
    assert_eq!(inspected.current_head, blank_head());

    let initialized = head(1);
    let mut post_drain = acquired.clone();
    post_drain.head = initialized.clone();
    let request = LifecyclePersistentInitializationCommitRequest {
        binding: Box::new(binding.clone()),
        format_plan_digest: Sha256Digest::from_bytes([75; 32]),
        initialization_token: random_id(702),
        filesystem_uuid: random_id(700),
        expected_blank_head: blank_head(),
        initialized_head: initialized.clone(),
        guest_probe: Box::new(LifecyclePersistentInitializationGuestProbe {
            challenge: random_id(703),
            runtime_incarnation: random_id(704),
            guest_device_serial: volume.guest_device_serial.clone(),
            guest_device_slot: volume.guest_device_slot,
            device_major: 252,
            device_minor: 1,
            size_bytes: volume.size_bytes,
            filesystem_uuid: random_id(700),
            filesystem_state: LifecyclePersistentGuestFilesystemState::ExactExt4Unmounted,
            guest_response_digest: Sha256Digest::from_bytes([72; 32]),
        }),
        flush_drain: Box::new(LifecyclePersistentInitializationFlushDrainReceipt {
            guest_flush_challenge: random_id(705),
            guest_flush_response_digest: Sha256Digest::from_bytes([73; 32]),
            blockd_drain_receipt_digest: Sha256Digest::from_bytes([74; 32]),
            durability: WireLifecycleVolumeDurabilityProof {
                scope: wire_command_scope,
                volume: WireLifecycleVolumeTarget {
                    disk_id: volume.disk_id.clone(),
                    disk_role: DiskRole::Persistent,
                    volume_id: volume.volume_id.clone(),
                    attachment_id: owner.attachment_id.clone(),
                    attachment_epoch: owner.attachment_epoch,
                },
                remote_head: initialized.clone(),
                local_durable_generation: initialized.generation,
                remote_durable_generation: initialized.generation,
                pending_pack_count: WireU64::new(0).unwrap(),
            },
        }),
    };
    let first_time = time(20_000);
    let (initialized_state, first_receipt) =
        commit_persistent_initialization(&request, &post_drain, &owner, &initial, None, first_time)
            .unwrap();
    assert!(matches!(
        &initialized_state,
        LifecyclePersistentInitializationState::Initialized {
            initialized_at,
            initialized_head,
            ..
        } if *initialized_at == first_time && initialized_head == &initialized
    ));

    let mut later = post_drain.clone();
    later.head = head(2);
    let (replayed_state, replayed_receipt) = commit_persistent_initialization(
        &request,
        &later,
        &owner,
        &initialized_state,
        Some(&first_receipt),
        time(99_999),
    )
    .unwrap();
    assert_eq!(replayed_state, initialized_state);
    assert_eq!(replayed_receipt, first_receipt);
    let conflicting_replays = [
        {
            let mut changed = request.clone();
            changed.format_plan_digest = Sha256Digest::from_bytes([76; 32]);
            changed
        },
        {
            let mut changed = request.clone();
            changed.guest_probe.challenge = random_id(706);
            changed
        },
        {
            let mut changed = request.clone();
            changed.guest_probe.runtime_incarnation = random_id(707);
            changed
        },
        {
            let mut changed = request.clone();
            changed.guest_probe.guest_device_serial = id("persistent-init-other-device");
            changed
        },
        {
            let mut changed = request.clone();
            changed.guest_probe.guest_device_slot += 1;
            changed
        },
        {
            let mut changed = request.clone();
            changed.guest_probe.device_major += 1;
            changed
        },
        {
            let mut changed = request.clone();
            changed.guest_probe.device_minor += 1;
            changed
        },
        {
            let mut changed = request.clone();
            changed.guest_probe.size_bytes += 4096;
            changed
        },
        {
            let mut changed = request.clone();
            changed.guest_probe.filesystem_uuid = random_id(709);
            changed
        },
        {
            let mut changed = request.clone();
            changed.guest_probe.guest_response_digest = Sha256Digest::from_bytes([77; 32]);
            changed
        },
        {
            let mut changed = request.clone();
            changed.flush_drain.guest_flush_challenge = random_id(708);
            changed
        },
        {
            let mut changed = request.clone();
            changed.flush_drain.guest_flush_response_digest = Sha256Digest::from_bytes([78; 32]);
            changed
        },
        {
            let mut changed = request.clone();
            changed.flush_drain.blockd_drain_receipt_digest = Sha256Digest::from_bytes([79; 32]);
            changed
        },
        {
            let mut changed = request.clone();
            changed.flush_drain.durability.volume.attachment_id =
                id("attachment-persistent-init-other");
            changed
        },
        {
            let mut changed = request.clone();
            changed.flush_drain.durability.volume.attachment_epoch = fence_epoch(2);
            changed
        },
        {
            let mut changed = request.clone();
            let changed_head = head(2);
            changed.initialized_head = changed_head.clone();
            changed.flush_drain.durability.remote_head = changed_head.clone();
            changed.flush_drain.durability.local_durable_generation = changed_head.generation;
            changed.flush_drain.durability.remote_durable_generation = changed_head.generation;
            changed
        },
        {
            let mut changed = request.clone();
            changed.flush_drain.durability.pending_pack_count = WireU64::new(1).unwrap();
            changed
        },
    ];
    for changed in conflicting_replays {
        assert_eq!(
            commit_persistent_initialization(
                &changed,
                &later,
                &owner,
                &initialized_state,
                Some(&first_receipt),
                time(99_999),
            ),
            Err(LifecycleVolumeError::PersistentInitializationMismatch)
        );
    }
    assert_eq!(
        commit_persistent_initialization(
            &request,
            &later,
            &owner,
            &initialized_state,
            None,
            time(99_999),
        ),
        Err(LifecycleVolumeError::PersistentInitializationMismatch)
    );
    assert_eq!(
        inspect_persistent_initialization(&binding, &later, &owner, &initialized_state)
            .unwrap()
            .current_head,
        later.head
    );

    // Alternate crash-after-format path: the same Start renews its exact
    // attachment before the first initialization commit. The immutable blank
    // lineage comes from `serving_acquire`, not the renewal's current head.
    let renew_request = LifecycleRenewLeaseRequest {
        volume_id: volume.volume_id.clone(),
        attachment_id: owner.attachment_id.clone(),
        expected_epoch: owner.attachment_epoch,
        lease_duration_ms: WireU64::new(90_000).unwrap(),
    };
    let (renewed_volume, authority_renewal) = renew_lease(
        &post_drain,
        &cats_storage::authority::RenewLeaseRequest {
            volume_id: renew_request.volume_id.clone(),
            attachment_id: renew_request.attachment_id.clone(),
            expected_epoch: renew_request.expected_epoch,
            lease_duration_ms: renew_request.lease_duration_ms.get(),
        },
        time(30_000),
    )
    .unwrap();
    let LifecycleStartVolumeGrantAuthority::NormalAcquire {
        request: original_acquire_request,
        result: original_acquire_result,
    } = &binding.start_grant.receipt.authority
    else {
        unreachable!()
    };
    let renewed_grant_receipt = LifecycleCommandStartVolumeGrantReceipt {
        scope: binding.scope.clone(),
        grant_sequence: WireU64::new(1).unwrap(),
        volume: volume.clone(),
        authority: LifecycleStartVolumeGrantAuthority::RenewSameNode {
            expected_source: VolumeTransitionSource::Lifecycle {
                operation_id: command_scope.operation_id.clone(),
                request_fingerprint: command_scope.request_fingerprint.clone(),
            },
            serving_acquire: Box::new(LifecycleServingAcquire::Normal {
                request: original_acquire_request.clone(),
                result: original_acquire_result.clone(),
            }),
            request: renew_request,
            result: LifecycleRenewLeaseResult {
                volume_id: authority_renewal.volume_id,
                attachment_id: authority_renewal.attachment_id,
                epoch: authority_renewal.epoch,
                resulting_head: renewed_volume.head.clone(),
                lease_expires_at: authority_renewal.lease_expires_at,
            },
        },
    };
    let renewed_grant_digest = command_start_volume_grant_receipt_digest(
        &command_scope,
        WireU64::new(1).unwrap(),
        &volume,
        &renewed_volume,
        &renewed_grant_receipt,
    )
    .unwrap();
    let mut renewed_request = request.clone();
    renewed_request.binding.start_grant = LifecycleStoredStartVolumeGrant {
        receipt: renewed_grant_receipt,
        receipt_digest: renewed_grant_digest,
    };
    let renewed_time = time(40_000);
    let (renewed_state, renewed_commit) = commit_persistent_initialization(
        &renewed_request,
        &renewed_volume,
        &owner,
        &initial,
        None,
        renewed_time,
    )
    .unwrap();
    let mut renewed_later = renewed_volume.clone();
    renewed_later.head = head(3);
    let (renewed_replay_state, renewed_replay_commit) = commit_persistent_initialization(
        &renewed_request,
        &renewed_later,
        &owner,
        &renewed_state,
        Some(&renewed_commit),
        time(100_000),
    )
    .unwrap();
    assert_eq!(renewed_replay_state, renewed_state);
    assert_eq!(renewed_replay_commit, renewed_commit);
    assert!(matches!(
        renewed_state,
        LifecyclePersistentInitializationState::Initialized { initialized_at, .. }
            if initialized_at == renewed_time
    ));

    let mut wrong_head = request.clone();
    let conflicting_head = head(4);
    wrong_head.initialized_head = conflicting_head.clone();
    wrong_head.flush_drain.durability.remote_head = conflicting_head.clone();
    wrong_head.flush_drain.durability.local_durable_generation = conflicting_head.generation;
    wrong_head.flush_drain.durability.remote_durable_generation = conflicting_head.generation;
    assert_eq!(
        commit_persistent_initialization(
            &wrong_head,
            &post_drain,
            &owner,
            &initial,
            None,
            first_time,
        ),
        Err(LifecycleVolumeError::PersistentInitializationMismatch)
    );
    let mut wrong_uuid = request.clone();
    wrong_uuid.guest_probe.filesystem_uuid = random_id(799);
    assert_eq!(
        commit_persistent_initialization(
            &wrong_uuid,
            &post_drain,
            &owner,
            &initial,
            None,
            first_time,
        ),
        Err(LifecycleVolumeError::PersistentInitializationMismatch)
    );
    let mut partial = request.clone();
    partial.flush_drain.durability.pending_pack_count = WireU64::new(1).unwrap();
    assert_eq!(
        commit_persistent_initialization(&partial, &post_drain, &owner, &initial, None, first_time,),
        Err(LifecycleVolumeError::PersistentInitializationMismatch)
    );
    let mut wrong_owner = owner;
    wrong_owner.owner_node_id = id("node-other");
    assert_eq!(
        commit_persistent_initialization(
            &request,
            &post_drain,
            &wrong_owner,
            &initial,
            None,
            first_time,
        ),
        Err(LifecycleVolumeError::PersistentInitializationMismatch)
    );
}
