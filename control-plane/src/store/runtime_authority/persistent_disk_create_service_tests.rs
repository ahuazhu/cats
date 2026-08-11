//! PostgreSQL acceptance for synchronous PersistentDisk create.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cats_api::error::ErrorCode;
use cats_api::resources::Disk;
use cats_api::runtime_reconciliation::{FenceEpoch, Generation, Id, RandomId128, UnixMillis};
use cats_storage::authority::{RemoteHead, VolumeAdminState, VolumeDurability, VolumeRecord};

use super::persistent_disk_create_service::{
    parse_authorized_persistent_disk_create, PersistentDiskCreateHttpFields,
    PersistentDiskCreateService,
};
use super::product::{DiskAdminState, DiskRecord, DiskRole, PersistentDiskInitialization};
use super::product_identity::ProductIdentitySource;
use super::product_rows::insert_disk;
use super::rows::insert_volume;
use crate::store::{Result, Store};

fn id(value: impl Into<String>) -> Id {
    Id::new(value).unwrap()
}

fn fields(key: &str) -> PersistentDiskCreateHttpFields {
    PersistentDiskCreateHttpFields {
        content_type: vec![b"application/json".to_vec()],
        content_encoding: Vec::new(),
        if_match: Vec::new(),
        idempotency_key: vec![key.as_bytes().to_vec()],
    }
}

fn body(name: &str, size_bytes: u64) -> Vec<u8> {
    format!(r#"{{"durability":"strict","name":"{name}","size_bytes":{size_bytes}}}"#).into_bytes()
}

fn ingress(
    workspace: &Id,
    name: &str,
    key: &str,
    size_bytes: u64,
) -> super::persistent_disk_create_service::AuthorizedPersistentDiskCreateIngress {
    parse_authorized_persistent_disk_create(
        workspace,
        Instant::now(),
        format!("/v1/workspaces/{workspace}/disks").as_bytes(),
        &fields(key),
        &body(name, size_bytes),
    )
    .unwrap()
}

#[derive(Default)]
struct SequentialIdentities(AtomicU64);

impl SequentialIdentities {
    fn starting_after(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }
}

impl ProductIdentitySource for SequentialIdentities {
    fn random_id(&self) -> Result<RandomId128> {
        let value = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(RandomId128::new(format!("{value:032x}")).unwrap())
    }
}

fn fixture(
    slug: &str,
) -> (
    tokio::runtime::Runtime,
    Arc<Store>,
    Id,
    Arc<SequentialIdentities>,
    PersistentDiskCreateService,
) {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Arc::new(Store::connect(&url, None).unwrap());
    let workspace = super::product_tests::bootstrap_workspace(&store, slug);
    let identities = Arc::new(SequentialIdentities::default());
    let service = PersistentDiskCreateService::new(
        Arc::clone(&store),
        Arc::clone(&identities) as Arc<dyn ProductIdentitySource>,
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    (runtime, store, workspace, identities, service)
}

fn blank_volume(volume_id: &str) -> VolumeRecord {
    VolumeRecord {
        volume_id: id(volume_id),
        size_bytes: 1,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        head: RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        },
        lease_owner: None,
        lease_epoch: FenceEpoch::new(0).unwrap(),
        lease_expires_at: None,
        last_transition: None,
    }
}

fn seed_persistent_disk(
    store: &Store,
    workspace: &Id,
    disk_id: &str,
    volume_id: &str,
    name: &str,
    token: u128,
    filesystem_uuid: u128,
) {
    let volume = blank_volume(volume_id);
    let disk = DiskRecord {
        disk_id: id(disk_id),
        workspace_id: workspace.clone(),
        name: id(name),
        volume_id: volume.volume_id.clone(),
        size_bytes: volume.size_bytes,
        durability: volume.durability,
        created_at: UnixMillis::new(1).unwrap(),
        admin_state: DiskAdminState::Active,
        role: DiskRole::Persistent {
            initialization: Box::new(PersistentDiskInitialization::Uninitialized {
                initialization_token: RandomId128::new(format!("{token:032x}")).unwrap(),
                filesystem_uuid: RandomId128::new(format!("{filesystem_uuid:032x}")).unwrap(),
                expected_blank_head: volume.head.clone(),
            }),
        },
    };
    store
        .authority_transaction(|transaction| {
            insert_volume(transaction, &volume)?;
            insert_disk(transaction, &disk)
        })
        .unwrap();
}

#[test]
fn strict_ingress_binds_raw_path_body_and_header_occurrences() {
    let workspace = id("ws_01");
    let parsed = parse_authorized_persistent_disk_create(
        &workspace,
        Instant::now(),
        b"/v1/workspaces/ws_01/disks",
        &fields("  exact-key\t"),
        &body("data", 4_194_304),
    )
    .unwrap();
    assert_eq!(parsed.idempotency().idempotency_key.as_str(), "exact-key");
    assert_eq!(
        parsed.idempotency().request_fingerprint.as_str(),
        "sha256:9cd24d6fcf7f90415fdbc71e15ae08fb6f181cb76c6f020f7aa8df94d18d0d62"
    );

    let mut boundary = body("data", 4_194_304);
    boundary.resize(4096, b' ');
    parse_authorized_persistent_disk_create(
        &workspace,
        Instant::now(),
        b"/v1/workspaces/ws_01/disks",
        &fields("boundary"),
        &boundary,
    )
    .unwrap();
    boundary.push(b' ');
    assert!(parse_authorized_persistent_disk_create(
        &workspace,
        Instant::now(),
        b"/v1/workspaces/ws_01/disks",
        &fields("boundary"),
        &boundary,
    )
    .is_err());

    let valid_body = body("data", 4_194_304);
    let mut malformed = Vec::new();
    let mut duplicate_type = fields("key");
    duplicate_type
        .content_type
        .push(b"application/json".to_vec());
    malformed.push((
        b"/v1/workspaces/ws_01/disks".as_slice(),
        duplicate_type,
        valid_body.clone(),
    ));
    let mut encoded = fields("key");
    encoded.content_encoding = vec![b"gzip".to_vec()];
    malformed.push((
        b"/v1/workspaces/ws_01/disks".as_slice(),
        encoded,
        valid_body.clone(),
    ));
    let mut if_match = fields("key");
    if_match.if_match = vec![b"1".to_vec()];
    malformed.push((
        b"/v1/workspaces/ws_01/disks".as_slice(),
        if_match,
        valid_body.clone(),
    ));
    let mut no_key = fields("key");
    no_key.idempotency_key.clear();
    malformed.push((
        b"/v1/workspaces/ws_01/disks".as_slice(),
        no_key,
        valid_body.clone(),
    ));
    let mut duplicate_key = fields("key");
    duplicate_key.idempotency_key.push(b"key".to_vec());
    malformed.push((
        b"/v1/workspaces/ws_01/disks".as_slice(),
        duplicate_key,
        valid_body.clone(),
    ));
    malformed.push((
        b"/v1/workspaces/ws_01/disks?x=1".as_slice(),
        fields("key"),
        valid_body.clone(),
    ));
    malformed.push((
        b"/v1/workspaces/ws_02/disks".as_slice(),
        fields("key"),
        valid_body.clone(),
    ));
    malformed.push((
        b"/v1/workspaces/ws_01/disks".as_slice(),
        fields("key"),
        br#"{"durability":"strict","name":"data","size_bytes":1,"unknown":true}"#.to_vec(),
    ));
    for invalid in [
        br#"{"durability":"strict","name":"data","name":"other","size_bytes":1}"#.as_slice(),
        br#"{"durability":"strict","name":"data","size_bytes":0}"#,
        br#"{"durability":"strict","name":"data","size_bytes":1099511627777}"#,
        br#"{"durability":"strict","name":"data"}"#,
    ] {
        malformed.push((
            b"/v1/workspaces/ws_01/disks".as_slice(),
            fields("key"),
            invalid.to_vec(),
        ));
    }
    for (path, fields, body) in malformed {
        assert!(parse_authorized_persistent_disk_create(
            &workspace,
            Instant::now(),
            path,
            &fields,
            &body,
        )
        .is_err());
    }
}

#[test]
fn create_replay_name_conflict_and_response_loss_preserve_one_atomic_resource() {
    let (runtime, store, workspace, identities, service) = fixture("persistent-create");
    store.inject_committed_response_loss_once();
    let first = runtime
        .block_on(service.create(ingress(&workspace, "data", "first-key", 4_194_304)))
        .unwrap();
    assert_eq!(first.http_status, 201);
    assert_eq!(first.content_type, Some("application/json"));
    let public: Disk = serde_json::from_slice(&first.response_body).unwrap();
    assert_eq!(public.id, "disk_00000000000000000000000000000001");
    assert_eq!(public.volume_id, "vol_00000000000000000000000000000002");
    assert_eq!(public.name, "data");

    let replay = runtime
        .block_on(service.create(ingress(&workspace, "data", "first-key", 4_194_304)))
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(identities.0.load(Ordering::SeqCst), 4);

    let wrong_fingerprint = runtime
        .block_on(service.create(ingress(&workspace, "other", "first-key", 4_194_304)))
        .unwrap_err();
    assert_eq!(wrong_fingerprint.error_code(), ErrorCode::Conflict);
    assert_eq!(identities.0.load(Ordering::SeqCst), 4);

    let occupied = runtime
        .block_on(service.create(ingress(&workspace, "data", "second-key", 4_194_304)))
        .unwrap();
    assert_eq!(occupied.http_status, 409);
    assert_eq!(
        occupied.response_body,
        br#"{"code":"already_exists","message":"disk name already exists"}"#
    );
    let occupied_replay = runtime
        .block_on(service.create(ingress(&workspace, "data", "second-key", 4_194_304)))
        .unwrap();
    assert_eq!(occupied_replay, occupied);

    let (volume, disk, result, operations, legacy_disks): (i64, i64, i64, i64, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM volume_records),
                        (SELECT count(*) FROM disk_records),
                        (SELECT count(*) FROM api_idempotency_results),
                        (SELECT count(*) FROM runtime_operations),
                        (SELECT count(*) FROM disks)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
        })
        .unwrap();
    assert_eq!(
        (volume, disk, result, operations, legacy_disks),
        (1, 1, 2, 0, 0)
    );
    let (volume_json, disk_json): (String, String) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT v.record::text, d.record::text
                       FROM volume_records v JOIN disk_records d USING (volume_id)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    let volume: VolumeRecord = serde_json::from_str(&volume_json).unwrap();
    let disk: DiskRecord = serde_json::from_str(&disk_json).unwrap();
    assert_eq!(disk.created_at.get() / 1_000, public.created_at_unix as u64);
    assert_eq!(disk.volume_id, volume.volume_id);
    assert_eq!(disk.size_bytes, volume.size_bytes);
    assert_eq!(disk.durability, volume.durability);
    assert!(matches!(
        disk.admin_state,
        super::product::DiskAdminState::Active
    ));
    match disk.role {
        DiskRole::Persistent { initialization } => match *initialization {
            PersistentDiskInitialization::Uninitialized {
                initialization_token,
                filesystem_uuid,
                expected_blank_head,
            } => {
                assert_eq!(
                    initialization_token.as_str(),
                    "00000000000000000000000000000003"
                );
                assert_eq!(filesystem_uuid.as_str(), "00000000000000000000000000000004");
                assert_eq!(expected_blank_head, volume.head);
            }
            other => panic!("unexpected PersistentDisk initialization: {other:?}"),
        },
        other => panic!("unexpected Disk role: {other:?}"),
    }
    assert!(matches!(volume.admin_state, VolumeAdminState::Active));
    assert_eq!(volume.lease_epoch.get(), 0);
    assert!(volume.lease_owner.is_none());
    assert!(volume.lease_expires_at.is_none());
    assert!(volume.last_transition.is_none());
    assert_eq!(volume.head.generation.get(), 0);
    assert!(volume.head.root_hash.is_none());
    assert!(volume.head.root_object_id.is_none());
}

#[test]
fn committed_owner_survives_handler_abort_and_shutdown_waits_for_resolution() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Arc::new(Store::connect(&url, None).unwrap());
    let workspace = super::product_tests::bootstrap_workspace(&store, "disk-owner-abort");
    let service = Arc::new(PersistentDiskCreateService::new(
        Arc::clone(&store),
        Arc::new(SequentialIdentities::default()),
    ));
    store.inject_committed_response_loss_once_after(std::time::Duration::from_millis(1_500));
    let observer = Store::connect(&url, None).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let request = ingress(&workspace, "data", "owner-abort", 4_194_304);
    let handler = runtime.spawn({
        let service = Arc::clone(&service);
        async move { service.create(request).await }
    });

    runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let counts: (i64, i64, i64) = observer
                    .with(|client| {
                        client
                            .query_one(
                                "SELECT
                                    (SELECT count(*) FROM volume_records),
                                    (SELECT count(*) FROM disk_records),
                                    (SELECT count(*) FROM api_idempotency_results)",
                                &[],
                            )
                            .map(|row| (row.get(0), row.get(1), row.get(2)))
                    })
                    .unwrap();
                if counts == (1, 1, 1) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the real PostgreSQL commit must become visible");
        assert!(
            !handler.is_finished(),
            "the injected response-loss delay must retain the request"
        );
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());

        let shutdown = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.shutdown_commit_resolutions().await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !shutdown.is_finished(),
            "shutdown returned while the detached commit owner was unresolved"
        );
        tokio::time::timeout(std::time::Duration::from_secs(3), shutdown)
            .await
            .expect("commit resolution must converge")
            .unwrap()
            .unwrap();
        assert!(service
            .create(ingress(&workspace, "data", "owner-abort", 4_194_304))
            .await
            .is_err());
    });
    assert_eq!(service.active_commit_resolutions(), 0);
}

#[test]
fn candidate_collision_retries_with_a_fresh_four_identity_bundle() {
    for (slug, seed) in [
        ("persistent-collision-volume", "volume"),
        ("persistent-collision-disk", "disk"),
        ("persistent-collision-token", "token"),
        ("persistent-collision-uuid", "uuid"),
    ] {
        let (runtime, store, workspace, identities, service) = fixture(slug);
        match seed {
            "volume" => store
                .authority_transaction(|transaction| {
                    insert_volume(
                        transaction,
                        &blank_volume("vol_00000000000000000000000000000002"),
                    )
                })
                .unwrap(),
            "disk" => seed_persistent_disk(
                &store,
                &workspace,
                "disk_00000000000000000000000000000001",
                "seed_volume",
                "seed-disk",
                900,
                901,
            ),
            "token" => seed_persistent_disk(
                &store,
                &workspace,
                "seed_token_disk",
                "seed_token_volume",
                "seed-token",
                3,
                901,
            ),
            "uuid" => seed_persistent_disk(
                &store,
                &workspace,
                "seed_uuid_disk",
                "seed_uuid_volume",
                "seed-uuid",
                900,
                4,
            ),
            _ => unreachable!(),
        }

        let result = runtime
            .block_on(service.create(ingress(&workspace, "data", "key", 1)))
            .unwrap();
        let public: Disk = serde_json::from_slice(&result.response_body).unwrap();
        assert_eq!(public.id, "disk_00000000000000000000000000000005");
        assert_eq!(public.volume_id, "vol_00000000000000000000000000000006");
        assert_eq!(identities.0.load(Ordering::SeqCst), 8);
        let identities: (String, String) = store
            .with(|client| {
                client
                    .query_one(
                        "SELECT initialization_token, filesystem_uuid
                           FROM disk_records WHERE disk_id=$1",
                        &[&public.id],
                    )
                    .map(|row| (row.get(0), row.get(1)))
            })
            .unwrap();
        assert_eq!(identities.0, "00000000000000000000000000000007");
        assert_eq!(identities.1, "00000000000000000000000000000008");
        assert_eq!(service.active_commit_resolutions(), 0);
    }
}

#[test]
fn concurrent_name_claims_across_store_replicas_publish_one_resource_and_two_results() {
    let url = crate::testsupport::isolated_control_store_url();
    let first_store = Arc::new(Store::connect(&url, None).unwrap());
    let second_store = Arc::new(Store::connect(&url, None).unwrap());
    let workspace = super::product_tests::bootstrap_workspace(&first_store, "disk-name-race");
    let first = Arc::new(PersistentDiskCreateService::new(
        Arc::clone(&first_store),
        Arc::new(SequentialIdentities::starting_after(0)),
    ));
    let second = Arc::new(PersistentDiskCreateService::new(
        Arc::clone(&second_store),
        Arc::new(SequentialIdentities::starting_after(100)),
    ));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let (first_result, second_result) = runtime.block_on(async {
        tokio::join!(
            first.create(ingress(&workspace, "shared", "key-a", 1)),
            second.create(ingress(&workspace, "shared", "key-b", 1)),
        )
    });
    let mut statuses = [
        first_result.unwrap().http_status,
        second_result.unwrap().http_status,
    ];
    statuses.sort_unstable();
    assert_eq!(statuses, [201, 409]);
    let counts: (i64, i64, i64) = first_store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM volume_records),
                        (SELECT count(*) FROM disk_records),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2)))
        })
        .unwrap();
    assert_eq!(counts, (1, 1, 2));
}
