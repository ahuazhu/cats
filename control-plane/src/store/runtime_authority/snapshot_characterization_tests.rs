use cats_protocol::error::ErrorCode;
use cats_protocol::runtime_reconciliation::{Id, RandomId128};

use super::semantic_persistent_disk::{SemanticStrictDeleteState, SemanticStrictPersistentDisk};
use crate::store::semantic::{
    AdmitCatActionOutcome, AdmitCatCreateOutcome, AtomicCatCreate, AttachDiskOutcome, CatAction,
    CatState, DeletePersistentDiskOutcome, DetachDiskOutcome, FinishCatAction, NewCat,
    NewCatMount, NodeRegistration, SemanticCatSelector,
};
use crate::store::Store;

const ROOT_HASH: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ROOT_OBJECT_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const COMMIT_RECEIPT_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn candidate() -> SemanticStrictPersistentDisk {
    SemanticStrictPersistentDisk {
        disk_id: Id::new(format!("disk_{}", "1".repeat(32))).unwrap(),
        workspace_id: Id::new("ws_snapshot_delete").unwrap(),
        name: Id::new("data").unwrap(),
        volume_id: Id::new(format!("vol_{}", "2".repeat(32))).unwrap(),
        size_bytes: 4 * 1024 * 1024,
        initialization_token: RandomId128::new("3".repeat(32)).unwrap(),
        filesystem_uuid: RandomId128::new("4".repeat(32)).unwrap(),
        delete_id: Id::new(format!("delete_{}", "5".repeat(32))).unwrap(),
    }
}

fn store() -> Store {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    initialize_product_scope(&store);
    store
}

fn initialize_product_scope(store: &Store) {
    store
        .with(|client| {
            client.batch_execute(
                "INSERT INTO accounts (
                    id,slug,display_name,kind,workos_organization_id,billing_account_id,
                    personal_owner_user_id,status,created_at
                 ) VALUES (
                    'acct_snapshot_delete','snapshot-delete','Snapshot Delete',
                    'organization','org_snapshot_delete','billing_snapshot_delete',
                    NULL,'active',1
                 );
                 INSERT INTO workspaces (
                    id,account_id,slug,display_name,is_default,created_at
                 ) VALUES (
                    'ws_snapshot_delete','acct_snapshot_delete','default','Default',TRUE,1
                 );",
            )
        })
        .unwrap();
}

fn store_pair() -> (Store, Store) {
    let url = crate::testsupport::isolated_control_store_url();
    let first = Store::connect(&url, None).unwrap();
    initialize_product_scope(&first);
    let second = Store::connect(&url, None).unwrap();
    (first, second)
}

fn register_node(store: &Store) {
    store
        .register_semantic_node(NodeRegistration {
            node_id: "node_snapshot_gc",
            node_name: "snapshot-gc-worker",
            control_endpoint: "http://127.0.0.1:9191",
            vendor: "test",
            region: "local",
            zone: "local-a",
            instance_id: "snapshot-gc-instance",
            machine_type: "test.large",
            node_version: "test",
            reset_completed: false,
        })
        .unwrap();
}

fn mark_gc_required(store: &Store, candidate: &SemanticStrictPersistentDisk) {
    store
        .with(|client| {
            client.execute(
                "UPDATE volume_records
                    SET record=jsonb_set(record,'{gc_required}','true'::jsonb),
                        gc_required=TRUE
                  WHERE volume_id=$1",
                &[&candidate.volume_id.as_str()],
            )?;
            Ok(())
        })
        .unwrap();
}

fn create_cold_cat(store: &Store) {
    register_node(store);
    let created = match store
        .create_semantic_cat(NewCat {
            cat_id: "cat_snapshot_gc",
            workspace_id: "ws_snapshot_delete",
            cat_slug: "snapshot-gc",
            node_id: "node_snapshot_gc",
            cpu_count: 1,
            memory_bytes: 1024 * 1024,
            boot_image: "sha256:snapshot-gc",
        })
        .unwrap()
    {
        crate::store::semantic::CreateCatOutcome::Created(cat) => cat,
        other => panic!("new Cat was not created: {other:?}"),
    };
    store
        .finish_semantic_cat_action(
            &created.cat_id,
            FinishCatAction {
                expected_action: CatAction::Create,
                expected_recovery_started_at: None,
                expected_node_id: Some("node_snapshot_gc"),
                expected_action_started_at: created.current_action_started_at.unwrap(),
                final_state: CatState::Cold,
                final_node_id: None,
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .expect("Create occurrence must settle");
}

fn insert_snapshot(store: &Store, candidate: &SemanticStrictPersistentDisk) {
    store
        .with(|client| {
            client.execute(
                "INSERT INTO disk_snapshots (
                    snapshot_id,workspace_id,snapshot_slug,disk_id,disk_slug,
                    volume_id,size_bytes,captured_generation,created_at,deleted_at
                 ) VALUES (
                    'snapshot_delete_guard','ws_snapshot_delete','delete-guard',$1,'data',
                    $2,$3,1,2,NULL
                 ) ON CONFLICT (snapshot_id) DO NOTHING",
                &[
                    &candidate.disk_id.as_str(),
                    &candidate.volume_id.as_str(),
                    &i64::try_from(candidate.size_bytes).unwrap(),
                ],
            )?;
            client.execute(
                "INSERT INTO disk_snapshot_records (
                    snapshot_id,record,disk_id,volume_id,size_bytes,
                    head_generation,head_root_hash,head_root_object_id,created_at
                 ) VALUES (
                    'snapshot_delete_guard',
                    jsonb_build_object('snapshot_id','snapshot_delete_guard',
                                       'disk_id',$1::TEXT,'volume_id',$2::TEXT,
                                       'size_bytes',$3::BIGINT,
                                       'head',jsonb_build_object(
                                           'generation',1,
                                           'root_hash',$4::TEXT,
                                           'root_object_id',$5::TEXT),
                                       'created_at',2),
                    $1,$2,$3,1,$4,$5,2
                 )",
                &[
                    &candidate.disk_id.as_str(),
                    &candidate.volume_id.as_str(),
                    &i64::try_from(candidate.size_bytes).unwrap(),
                    &ROOT_HASH,
                    &ROOT_OBJECT_ID,
                ],
            )?;
            Ok(())
        })
        .unwrap();
}

fn initialize_disk(store: &Store, candidate: &SemanticStrictPersistentDisk) {
    store
        .with(|client| {
            client.execute(
                "UPDATE volume_records SET
                    record=jsonb_set(record,'{head}',jsonb_build_object(
                        'generation',1,
                        'root_hash',$2::TEXT,
                        'root_object_id',$3::TEXT)),
                    head_generation=1,
                    head_root_hash=$2,
                    head_root_object_id=$3
                  WHERE volume_id=$1",
                &[&candidate.volume_id.as_str(), &ROOT_HASH, &ROOT_OBJECT_ID],
            )?;
            client.execute(
                "UPDATE disk_records SET
                    record=jsonb_set(record,'{role,initialization}',jsonb_build_object(
                        'kind','initialized',
                        'initialization_token',$2::TEXT,
                        'filesystem_uuid',$3::TEXT,
                        'expected_blank_head',jsonb_build_object(
                            'generation',0,'root_hash',NULL,'root_object_id',NULL),
                        'initialized_head',jsonb_build_object(
                            'generation',1,
                            'root_hash',$4::TEXT,
                            'root_object_id',$5::TEXT),
                        'initialized_at',2,
                        'commit_receipt_digest',$6::TEXT)),
                    initialization_kind='initialized',
                    initialized_generation=1,
                    initialized_root_hash=$4,
                    initialized_root_object_id=$5,
                    initialized_at=2,
                    initialization_commit_receipt_bytes=decode('01','hex'),
                    initialization_commit_receipt_digest=$6
                  WHERE disk_id=$1",
                &[
                    &candidate.disk_id.as_str(),
                    &candidate.initialization_token.as_str(),
                    &candidate.filesystem_uuid.as_str(),
                    &ROOT_HASH,
                    &ROOT_OBJECT_ID,
                    &COMMIT_RECEIPT_DIGEST,
                ],
            )?;
            client.execute(
                "INSERT INTO persistent_disks (
                    disk_id,workspace_id,disk_slug,size_bytes,volume_id,
                    filesystem_uuid,disk_format,status,created_at,deleted_at
                 ) VALUES ($1,$2,$3,$4,$5,$6,'ext4','normal',1,NULL)",
                &[
                    &candidate.disk_id.as_str(),
                    &candidate.workspace_id.as_str(),
                    &candidate.name.as_str(),
                    &i64::try_from(candidate.size_bytes).unwrap(),
                    &candidate.volume_id.as_str(),
                    &candidate.filesystem_uuid.as_str(),
                ],
            )?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn a_live_product_snapshot_blocks_both_disk_delete_phases() {
    let store = store();
    let candidate = candidate();
    store
        .ensure_semantic_strict_disk_created(&candidate)
        .unwrap();
    initialize_disk(&store, &candidate);

    insert_snapshot(&store, &candidate);
    let begin_error = store
        .begin_semantic_strict_disk_delete(&candidate)
        .unwrap_err();
    assert_eq!(begin_error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        begin_error.message,
        "PersistentDisk has a live DiskSnapshot"
    );

    store
        .with(|client| {
            client.execute(
                "DELETE FROM disk_snapshot_records WHERE snapshot_id='snapshot_delete_guard'",
                &[],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        store.begin_semantic_strict_disk_delete(&candidate).unwrap(),
        SemanticStrictDeleteState::Deleting
    );

    insert_snapshot(&store, &candidate);
    let complete_error = store
        .complete_semantic_strict_disk_delete(&candidate)
        .unwrap_err();
    assert_eq!(complete_error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        complete_error.message,
        "PersistentDisk has a live DiskSnapshot"
    );

    let still_present = store
        .with(|client| {
            let row = client.query_one(
                "SELECT EXISTS (
                    SELECT 1 FROM disk_records WHERE disk_id=$1
                 ) AND EXISTS (
                    SELECT 1 FROM volume_records WHERE volume_id=$2
                 )",
                &[&candidate.disk_id.as_str(), &candidate.volume_id.as_str()],
            )?;
            Ok(row.get::<_, bool>(0))
        })
        .unwrap();
    assert!(
        still_present,
        "failed complete-delete must retain both product and authority rows"
    );
}

#[test]
fn deleted_snapshot_replays_its_destroy_generation_after_storage_disk_removal() {
    let store = store();
    let candidate = candidate();
    store
        .ensure_semantic_strict_disk_created(&candidate)
        .unwrap();
    initialize_disk(&store, &candidate);
    insert_snapshot(&store, &candidate);

    let deleted = match store
        .delete_semantic_disk_snapshot("ws_snapshot_delete", "snapshot_delete_guard")
        .unwrap()
    {
        crate::store::semantic::DeleteDiskSnapshotOutcome::Deleted(snapshot) => snapshot,
        other => panic!("snapshot was not deleted: {other:?}"),
    };
    assert_eq!(deleted.deleted_head_generation, Some(1));

    assert_eq!(
        store.begin_semantic_strict_disk_delete(&candidate).unwrap(),
        SemanticStrictDeleteState::Deleting
    );
    store
        .complete_semantic_strict_disk_delete(&candidate)
        .unwrap();
    assert!(store.semantic_strict_disk_is_absent(&candidate).unwrap());

    let tombstone = store
        .find_semantic_snapshot_by_id("snapshot_delete_guard")
        .unwrap()
        .expect("snapshot tombstone survives its storage Disk");
    assert!(tombstone.deleted_at.is_some());
    assert_eq!(tombstone.deleted_head_generation, Some(1));
}

#[test]
fn garbage_collecting_keeps_disk_projection_readable_and_rejects_binding_mutations() {
    let store = store();
    let candidate = candidate();
    store
        .ensure_semantic_strict_disk_created(&candidate)
        .unwrap();
    initialize_disk(&store, &candidate);
    create_cold_cat(&store);
    assert!(matches!(
        store
            .attach_semantic_disk(
                "binding_snapshot_gc",
                "cat_snapshot_gc",
                candidate.disk_id.as_str(),
                "/data",
            )
            .unwrap(),
        AttachDiskOutcome::Attached(_)
    ));
    mark_gc_required(&store, &candidate);
    let claim = store
        .claim_next_snapshot_gc(std::time::Duration::from_secs(1))
        .unwrap()
        .expect("stable Cold binding is GC eligible");

    let product = store
        .find_semantic_disk_by_id(candidate.disk_id.as_str())
        .unwrap()
        .expect("product Disk exists");
    assert_eq!(store.semantic_disk_head_generation(&product).unwrap(), Some(1));
    assert_eq!(
        store
            .attach_semantic_disk(
                "binding_snapshot_gc",
                "cat_snapshot_gc",
                candidate.disk_id.as_str(),
                "/data",
            )
            .unwrap(),
        AttachDiskOutcome::DiskBusy
    );
    assert_eq!(
        store
            .detach_semantic_disk("cat_snapshot_gc", candidate.disk_id.as_str())
            .unwrap(),
        DetachDiskOutcome::DiskBusy
    );
    assert_eq!(
        store
            .delete_semantic_persistent_disk(candidate.disk_id.as_str())
            .unwrap(),
        DeletePersistentDiskOutcome::DiskBusy
    );
    assert!(matches!(
        store
            .admit_semantic_cat_action(
                SemanticCatSelector::Id("cat_snapshot_gc"),
                CatAction::Run,
            )
            .unwrap(),
        AdmitCatActionOutcome::Busy(_)
    ));
    assert!(matches!(
        store
            .admit_semantic_cat_action(
                SemanticCatSelector::Id("cat_snapshot_gc"),
                CatAction::Destroy,
            )
            .unwrap(),
        AdmitCatActionOutcome::Busy(_)
    ));
    assert_eq!(
        store.abort_snapshot_gc(&claim).unwrap(),
        super::snapshot_gc::SnapshotGcSettlement::Settled
    );
}

#[test]
fn gc_claim_and_initial_mount_create_serialize_on_the_disk_identity() {
    let (gc_store, create_store) = store_pair();
    let candidate = candidate();
    gc_store
        .ensure_semantic_strict_disk_created(&candidate)
        .unwrap();
    initialize_disk(&gc_store, &candidate);
    register_node(&gc_store);
    mark_gc_required(&gc_store, &candidate);

    let start = std::sync::Arc::new(std::sync::Barrier::new(3));
    let gc_start = start.clone();
    let gc = std::thread::spawn(move || {
        gc_start.wait();
        gc_store
            .claim_next_snapshot_gc(std::time::Duration::from_secs(1))
            .unwrap()
    });
    let create_start = start.clone();
    let disk_id = candidate.disk_id.to_string();
    let create = std::thread::spawn(move || {
        let mounts = [NewCatMount {
            binding_id: "binding_initial_gc_race",
            disk_id: &disk_id,
            mount_path: "/data",
        }];
        create_start.wait();
        create_store
            .admit_semantic_cat_create(AtomicCatCreate {
                cat_id: "cat_initial_gc_race",
                workspace_id: "ws_snapshot_delete",
                cat_slug: "initial-gc-race",
                cpu_count: 1,
                memory_bytes: 1024 * 1024,
                boot_image: "sha256:snapshot-gc",
                mounts: &mounts,
            })
            .unwrap()
    });
    start.wait();

    let claim = gc.join().unwrap();
    let create = create.join().unwrap();
    match (claim, create) {
        (
            Some(_),
            AdmitCatCreateOutcome::MountRejected { code, .. },
        ) if code == "disk_busy" => {}
        (None, AdmitCatCreateOutcome::Created(_)) => {}
        (claim, create) => panic!(
            "GC and initial binding escaped common exclusion: claim={claim:?}, create={create:?}"
        ),
    }
}
