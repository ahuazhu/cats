use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{Id, RandomId128};

use super::semantic_persistent_disk::{SemanticStrictDeleteState, SemanticStrictPersistentDisk};
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
    store
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
