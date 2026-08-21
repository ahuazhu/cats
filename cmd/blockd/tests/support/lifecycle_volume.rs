use std::collections::BTreeMap;

use cats_api::runtime_lifecycle::{
    DiskRole, PlacementIdentity, RuntimeVolumeConfig, RuntimeVolumeGuestBinding,
};
use cats_api::runtime_lifecycle_volume::{
    LifecycleCommandStartVolumeGrantReceipt, LifecycleStartVolumeGrantAuthority,
    LifecycleVolumeCommandScope,
};
use cats_api::runtime_reconciliation::{Epoch, Id, Sha256Digest, VolumeTransitionSource, WireU64};
use cats_control_plane::store::Store;
use cats_storage::authority::{
    authorized_serving_attachment_from_start_volume_grant, AuthorizedServingAttachment,
    LastVolumeTransition, VolumeRecord,
};
use cats_storage::lifecycle_volume::command_start_volume_grant_receipt_digest_from_closed_receipt;
use postgres::types::ToSql;
use postgres::{Client, NoTls};

const EMPTY_OBJECT_SHA256: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

pub(super) struct TestLifecycleScope {
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    cat_id: Id,
    node_id: Id,
    placement_epoch: Epoch,
    config_id: Id,
    config_digest: Sha256Digest,
}

impl TestLifecycleScope {
    pub(super) fn new(unique: &str, node_id: &str, placement_epoch: Epoch) -> Self {
        Self {
            operation_id: Id::new(format!("operation_{unique}")).unwrap(),
            request_fingerprint: Sha256Digest::new(EMPTY_OBJECT_SHA256).unwrap(),
            cat_id: Id::new(format!("cat_{unique}")).unwrap(),
            node_id: Id::new(node_id).unwrap(),
            placement_epoch,
            config_id: Id::new(format!("config_{unique}")).unwrap(),
            config_digest: Sha256Digest::new(EMPTY_OBJECT_SHA256).unwrap(),
        }
    }

    pub(super) fn source(&self) -> VolumeTransitionSource {
        VolumeTransitionSource::Lifecycle {
            operation_id: self.operation_id.clone(),
            request_fingerprint: self.request_fingerprint.clone(),
        }
    }

    pub(super) fn seed_operation(&self, store: &Store, postgres_url: &str) {
        store
            .ensure_configured_accounts(&BTreeMap::from([(
                "blockd-fixture".to_owned(),
                "org_blockd_fixture".to_owned(),
            )]))
            .unwrap();
        let account = store
            .account_for_organization("org_blockd_fixture")
            .unwrap()
            .unwrap();
        let workspace_id = store
            .workspaces_for_account(&account.id)
            .unwrap()
            .into_iter()
            .find(|workspace| workspace.is_default)
            .unwrap()
            .id;
        let placement_epoch = i64::try_from(self.placement_epoch.get()).unwrap();
        let creation_id = format!("creation_{}", self.operation_id);
        let empty_object: &[u8] = b"{}";
        let cat_parameters: [&(dyn ToSql + Sync); 5] = [
            &self.cat_id.as_str(),
            &workspace_id,
            &creation_id,
            &self.config_id.as_str(),
            &self.config_digest.as_str(),
        ];
        let config_parameters: [&(dyn ToSql + Sync); 5] = [
            &self.config_id.as_str(),
            &workspace_id,
            &self.cat_id.as_str(),
            &empty_object,
            &self.config_digest.as_str(),
        ];
        let operation_parameters: [&(dyn ToSql + Sync); 9] = [
            &self.operation_id.as_str(),
            &workspace_id,
            &self.cat_id.as_str(),
            &self.node_id.as_str(),
            &placement_epoch,
            &empty_object,
            &self.request_fingerprint.as_str(),
            &self.config_id.as_str(),
            &self.config_digest.as_str(),
        ];
        let mut client = Client::connect(postgres_url, NoTls).unwrap();
        let mut transaction = client.transaction().unwrap();
        transaction
            .execute(
                "INSERT INTO cat_records (
                        cat_id, record, workspace_id, name, cat_creation_id,
                        lifecycle_head_operation_id, stable_state,
                        effective_runtime_ready_operation_id, runtime_incarnation,
                        current_runtime_config_id, current_runtime_config_sha256,
                        created_at, deleted_at
                     ) VALUES (
                        $1, jsonb_build_object(
                            'cat_id', $1::TEXT,
                            'workspace_id', $2::TEXT,
                            'name', $1::TEXT
                        ), $2, $1, $3, NULL, NULL, NULL, NULL,
                        $4, $5, 1, NULL
                     )",
                &cat_parameters,
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO cat_runtime_configs (
                        config_id, workspace_id, cat_id, canonical_config_bytes,
                        canonical_config_sha256, created_at_unix_ms
                     ) VALUES ($1, $2, $3, $4, $5, 1)",
                &config_parameters,
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO runtime_operations (
                        operation_id, workspace_id, cat_id, node_id,
                        placement_epoch, command_kind, canonical_request_bytes,
                        canonical_request_sha256, runtime_config_id,
                        runtime_config_sha256,
                        expected_predecessor_operation_id, predecessor_kind,
                        expected_predecessor_result_kind,
                        expected_predecessor_result_sha256, state,
                        terminal_source, terminal_result_kind,
                        canonical_result_bytes, canonical_result_sha256,
                        created_at_unix_ms, terminal_at_unix_ms
                     ) VALUES (
                        $1, $2, $3, $4, $5, 'start', $6, $7, $8, $9,
                        NULL, 'genesis', NULL, NULL, 'unresolved', NULL,
                        NULL, NULL, NULL, 1, NULL
                     )",
                &operation_parameters,
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    pub(super) fn authorized_root_attachment(
        &self,
        record: &VolumeRecord,
        disk_id: &str,
        guest_serial: &str,
    ) -> AuthorizedServingAttachment {
        let LastVolumeTransition::NormalAcquire {
            source,
            request,
            result,
        } = record.last_transition.clone().unwrap()
        else {
            panic!("test authority did not install a normal acquire marker")
        };
        assert_eq!(source, self.source());
        let grant = LifecycleCommandStartVolumeGrantReceipt {
            scope: LifecycleVolumeCommandScope {
                operation_id: self.operation_id.clone(),
                request_fingerprint: self.request_fingerprint.clone(),
                cat_id: self.cat_id.clone(),
                node_id: self.node_id.clone(),
                placement_identity: PlacementIdentity {
                    node_id: self.node_id.clone(),
                    placement_epoch: self.placement_epoch,
                },
            },
            grant_sequence: WireU64::new(0).unwrap(),
            volume: RuntimeVolumeConfig {
                volume_id: record.volume_id.clone(),
                disk_id: Id::new(disk_id).unwrap(),
                disk_role: DiskRole::Root,
                size_bytes: record.size_bytes,
                durability: record.durability,
                guest_device_serial: Id::new(guest_serial).unwrap(),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            },
            authority: LifecycleStartVolumeGrantAuthority::NormalAcquire { request, result },
        };
        let digest = command_start_volume_grant_receipt_digest_from_closed_receipt(&grant).unwrap();
        authorized_serving_attachment_from_start_volume_grant(&grant, &digest, None).unwrap()
    }
}
