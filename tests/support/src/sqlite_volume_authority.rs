//! SQLite-backed Volume Authority fixture for data-plane tests.
//!
//! Production adapters deliberately expose no ownership mutation. Tests which
//! need an externally decided grant install it here, outside every production
//! crate, then exercise blockd only through its complete authorized input.

use std::fs::{self, File};
use std::path::Path;
use std::sync::{Arc, Mutex};

use cats_api::runtime_lifecycle_volume::{
    DiskRole, PlacementIdentity, RuntimeVolumeConfig, RuntimeVolumeGuestBinding,
};
use cats_api::runtime_lifecycle_volume::{
    LifecycleCommandStartVolumeGrantReceipt, LifecycleStartVolumeGrantAuthority,
    LifecycleVolumeCommandScope,
};
use cats_api::runtime_reconciliation::WireU64;
use cats_api::runtime_reconciliation::{
    AsciiText, Epoch, FenceEpoch, Generation, Id, NormalAcquireRequest, NormalAcquireResult,
    RandomId128, RemoteHead, Sha256Digest, VolumeTransitionSource,
};
use cats_storage::authority::{
    authorized_serving_attachment_from_start_volume_grant, AuthorityError,
    AuthorizedServingAttachment, LastVolumeTransition, RenewLeaseRequest, RenewLeaseResult,
    UnixMillis, VolumeAdminState, VolumeDataAuthority, VolumeDurability, VolumeHeadCasRequest,
    VolumeHeadCasResult, VolumeRecord,
};
use cats_storage::lifecycle_volume::command_start_volume_grant_receipt_digest_from_closed_receipt;
use rusqlite::{params, Connection, OptionalExtension};

const TEST_LEASE_EXPIRY: u64 = 8_000_000_000_000_000_000;

/// Installs the exact owner/epoch chosen by a test's external authority.
pub fn install_sqlite_grant(
    path: &Path,
    volume_id: &str,
    attachment_id: &str,
    epoch: i64,
) -> Result<(), String> {
    if epoch <= 0 {
        return Err("test attachment epoch must be positive".to_string());
    }
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let changed = connection
        .execute(
            "UPDATE volumes
                SET lease_owner=?2, lease_epoch=?3, lease_expires_at_ms=?4
              WHERE volume_id=?1",
            params![volume_id, attachment_id, epoch, i64::MAX],
        )
        .map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err(format!("test volume {volume_id} does not exist"));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SqliteTestVolumeGrant {
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub lease_duration_ms: u64,
    pub durability: VolumeDurability,
    pub node_id: Id,
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub placement_epoch: Epoch,
}

impl SqliteTestVolumeGrant {
    pub fn new(
        volume_id: &str,
        attachment_id: &str,
        attachment_epoch: i64,
        lease_duration_ms: u64,
        durability: VolumeDurability,
    ) -> Self {
        let epoch = u64::try_from(attachment_epoch).expect("test epoch is positive");
        Self {
            volume_id: Id::new(volume_id).expect("test volume ID is canonical"),
            attachment_id: Id::new(attachment_id).expect("test attachment ID is canonical"),
            attachment_epoch: FenceEpoch::new(epoch).expect("test epoch is in range"),
            lease_duration_ms,
            durability,
            node_id: Id::new("node_test").expect("constant Node ID is canonical"),
            operation_id: Id::new("operation_test").expect("constant Operation ID is canonical"),
            request_fingerprint: Sha256Digest::from_bytes([1; 32]),
            placement_epoch: Epoch::new(1).expect("one is an Epoch"),
        }
    }
}

/// Test-only adapter which projects the old SQLite fixture row through the
/// production read/renew/CAS data-plane port. It owns no acquire operation.
pub struct SqliteTestVolumeAuthority {
    connection: Mutex<Connection>,
    grant: SqliteTestVolumeGrant,
    request: NormalAcquireRequest,
    result: NormalAcquireResult,
    lease_expires_at: Mutex<UnixMillis>,
}

impl SqliteTestVolumeAuthority {
    pub fn open(path: &Path, grant: SqliteTestVolumeGrant) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|error| error.to_string())?;
        connection
            .busy_timeout(crate::wait::poll_bound())
            .map_err(|error| error.to_string())?;
        let head = load_head(&connection, &grant.volume_id)?;
        if head.lease_owner.as_ref() != Some(&grant.attachment_id)
            || head.lease_epoch != grant.attachment_epoch
        {
            return Err("installed SQLite grant does not match the test authority".to_string());
        }
        let transition_id = RandomId128::new(format!("{:032x}", grant.attachment_epoch.get()))
            .expect("positive epoch makes a nonzero test transition ID");
        let previous_epoch = FenceEpoch::new(grant.attachment_epoch.get() - 1)
            .expect("zero is a valid unowned epoch");
        let lease_expires_at = UnixMillis::new(TEST_LEASE_EXPIRY).expect("constant is in range");
        let request = NormalAcquireRequest {
            volume_id: grant.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: grant.attachment_id.clone(),
            expected_unowned_epoch: previous_epoch,
            placement_epoch: grant.placement_epoch,
            lease_duration_ms: grant.lease_duration_ms,
        };
        let result = NormalAcquireResult {
            volume_id: grant.volume_id.clone(),
            transition_id,
            attachment_id: grant.attachment_id.clone(),
            resulting_epoch: grant.attachment_epoch,
            resulting_head: head.head.clone(),
            lease_expires_at,
        };
        Ok(Self {
            connection: Mutex::new(connection),
            grant,
            request,
            result,
            lease_expires_at: Mutex::new(lease_expires_at),
        })
    }

    pub fn authorized_attachment(&self) -> AuthorizedServingAttachment {
        let current = self
            .load_volume(&self.grant.volume_id)
            .expect("installed test Volume is readable");
        let grant = LifecycleCommandStartVolumeGrantReceipt {
            scope: LifecycleVolumeCommandScope {
                operation_id: self.grant.operation_id.clone(),
                request_fingerprint: self.grant.request_fingerprint.clone(),
                cat_id: Id::new("cat_test").expect("constant Cat ID is canonical"),
                node_id: self.grant.node_id.clone(),
                placement_identity: PlacementIdentity {
                    node_id: self.grant.node_id.clone(),
                    placement_epoch: self.grant.placement_epoch,
                },
            },
            grant_sequence: WireU64::new(0).expect("zero is a grant sequence"),
            volume: RuntimeVolumeConfig {
                volume_id: self.grant.volume_id.clone(),
                disk_id: Id::new("disk_test").expect("constant Disk ID is canonical"),
                disk_role: DiskRole::Root,
                size_bytes: current.size_bytes,
                durability: self.grant.durability,
                guest_device_serial: Id::new("root-boot").expect("constant serial is canonical"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            },
            authority: LifecycleStartVolumeGrantAuthority::NormalAcquire {
                request: self.request.clone(),
                result: self.result.clone(),
            },
        };
        let digest = command_start_volume_grant_receipt_digest_from_closed_receipt(&grant)
            .expect("test Start grant is closed");
        authorized_serving_attachment_from_start_volume_grant(&grant, &digest, None)
            .expect("test Start grant converts to a serving attachment")
    }
}

/// Builds a complete serving grant and persists the lineage file blockd
/// requires before it adopts any local state.
pub fn prepare_sqlite_authorized_serving(
    metadata_path: &Path,
    data_dir: &Path,
    grant: SqliteTestVolumeGrant,
) -> Result<(AuthorizedServingAttachment, Arc<SqliteTestVolumeAuthority>), String> {
    let epoch = i64::try_from(grant.attachment_epoch.get())
        .map_err(|_| "test attachment epoch exceeds SQLite range".to_string())?;
    install_sqlite_grant(
        metadata_path,
        grant.volume_id.as_str(),
        grant.attachment_id.as_str(),
        epoch,
    )?;
    let authority = Arc::new(SqliteTestVolumeAuthority::open(metadata_path, grant)?);
    let attachment = authority.authorized_attachment();
    fs::create_dir_all(data_dir).map_err(|error| error.to_string())?;
    let identity_path = data_dir.join("identity.json");
    let identity_file = File::create(&identity_path).map_err(|error| error.to_string())?;
    serde_json::to_writer(&identity_file, &attachment.identity)
        .map_err(|error| error.to_string())?;
    identity_file
        .sync_all()
        .map_err(|error| error.to_string())?;
    File::open(data_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    Ok((attachment, authority))
}

impl VolumeDataAuthority for SqliteTestVolumeAuthority {
    fn load_volume(&self, volume_id: &Id) -> cats_storage::authority::Result<VolumeRecord> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::BackendUnknown)?;
        let mut record =
            load_head(&connection, volume_id).map_err(|_| AuthorityError::BackendUnknown)?;
        record.durability = self.grant.durability;
        record.lease_expires_at = record
            .lease_owner
            .as_ref()
            .map(|_| {
                self.lease_expires_at
                    .lock()
                    .map(|value| *value)
                    .map_err(|_| AuthorityError::BackendUnknown)
            })
            .transpose()?;
        record.last_transition = Some(LastVolumeTransition::NormalAcquire {
            source: VolumeTransitionSource::Lifecycle {
                operation_id: self.grant.operation_id.clone(),
                request_fingerprint: self.grant.request_fingerprint.clone(),
            },
            request: self.request.clone(),
            result: self.result.clone(),
        });
        Ok(record)
    }

    fn renew_lease(
        &self,
        request: &RenewLeaseRequest,
    ) -> cats_storage::authority::Result<RenewLeaseResult> {
        if request.volume_id != self.grant.volume_id
            || request.attachment_id != self.grant.attachment_id
            || request.expected_epoch != self.grant.attachment_epoch
            || request.lease_duration_ms != self.grant.lease_duration_ms
        {
            return Err(AuthorityError::Fenced);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::BackendUnknown)?;
        let changed = connection
            .execute(
                "UPDATE volumes SET lease_expires_at_ms=?4
                  WHERE volume_id=?1 AND lease_owner=?2 AND lease_epoch=?3",
                params![
                    request.volume_id.as_str(),
                    request.attachment_id.as_str(),
                    i64::try_from(request.expected_epoch.get())
                        .map_err(|_| AuthorityError::BackendUnknown)?,
                    i64::MAX
                ],
            )
            .map_err(|_| AuthorityError::BackendUnknown)?;
        if changed != 1 {
            return Err(AuthorityError::Fenced);
        }
        let expires = *self
            .lease_expires_at
            .lock()
            .map_err(|_| AuthorityError::BackendUnknown)?;
        Ok(RenewLeaseResult {
            volume_id: request.volume_id.clone(),
            attachment_id: request.attachment_id.clone(),
            epoch: request.expected_epoch,
            lease_expires_at: expires,
        })
    }

    fn compare_and_swap_head(
        &self,
        request: &VolumeHeadCasRequest,
    ) -> cats_storage::authority::Result<VolumeHeadCasResult> {
        let generation = i64::try_from(request.new_head.generation.get())
            .map_err(|_| AuthorityError::BackendUnknown)?;
        let expected_generation = i64::try_from(request.expected_head.generation.get())
            .map_err(|_| AuthorityError::BackendUnknown)?;
        let epoch = i64::try_from(request.expected_epoch.get())
            .map_err(|_| AuthorityError::BackendUnknown)?;
        let root_hash = request
            .new_head
            .root_hash
            .as_ref()
            .map(|hash| hash.as_bytes().to_vec());
        let root_object = request
            .new_head
            .root_object_id
            .as_ref()
            .map(|value| value.as_str());
        let expected_hash = request
            .expected_head
            .root_hash
            .as_ref()
            .map(|hash| hash.as_bytes().to_vec());
        let expected_object = request
            .expected_head
            .root_object_id
            .as_ref()
            .map(|value| value.as_str());
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::BackendUnknown)?;
        let changed = connection
            .execute(
                "UPDATE volumes
                    SET generation=?5, root_hash=?6, root_object_id=?7
                  WHERE volume_id=?1 AND lease_owner=?2 AND lease_epoch=?3
                    AND size_bytes=?4 AND generation=?8
                    AND root_hash IS ?9 AND root_object_id IS ?10",
                params![
                    request.volume_id.as_str(),
                    request.attachment_id.as_str(),
                    epoch,
                    i64::try_from(request.expected_size_bytes)
                        .map_err(|_| AuthorityError::BackendUnknown)?,
                    generation,
                    root_hash,
                    root_object,
                    expected_generation,
                    expected_hash,
                    expected_object
                ],
            )
            .map_err(|_| AuthorityError::BackendUnknown)?;
        if changed != 1 {
            let current = load_head(&connection, &request.volume_id)
                .map_err(|_| AuthorityError::BackendUnknown)?;
            if current.lease_owner.as_ref() != Some(&request.attachment_id)
                || current.lease_epoch != request.expected_epoch
            {
                return Err(AuthorityError::Fenced);
            }
            return Err(AuthorityError::HeadConflict);
        }
        Ok(VolumeHeadCasResult {
            volume_id: request.volume_id.clone(),
            attachment_id: request.attachment_id.clone(),
            epoch: request.expected_epoch,
            resulting_head: request.new_head.clone(),
        })
    }
}

fn load_head(connection: &Connection, volume_id: &Id) -> Result<VolumeRecord, String> {
    connection
        .query_row(
            "SELECT volume_id, size_bytes, generation, root_hash, root_object_id,
                    lease_owner, lease_epoch
               FROM volumes WHERE volume_id=?1",
            [volume_id.as_str()],
            |row| {
                let size: i64 = row.get(1)?;
                let generation: i64 = row.get(2)?;
                let hash: Option<Vec<u8>> = row.get(3)?;
                let lease_owner: Option<String> = row.get(5)?;
                let epoch: i64 = row.get(6)?;
                Ok((
                    row.get::<_, String>(0)?,
                    size,
                    generation,
                    hash,
                    row.get::<_, Option<String>>(4)?,
                    lease_owner,
                    epoch,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("test volume {volume_id} does not exist"))
        .and_then(|(id, size, generation, hash, object, owner, epoch)| {
            let root_hash = hash
                .map(|bytes| {
                    <[u8; 32]>::try_from(bytes)
                        .map(Sha256Digest::from_bytes)
                        .map_err(|_| "test root hash is not 32 bytes".to_string())
                })
                .transpose()?;
            Ok(VolumeRecord {
                volume_id: Id::new(id).ok_or_else(|| "test volume ID is invalid".to_string())?,
                size_bytes: u64::try_from(size).map_err(|_| "test size is negative".to_string())?,
                durability: VolumeDurability::Strict,
                admin_state: VolumeAdminState::Active,
                head: RemoteHead {
                    generation: Generation::new(
                        u64::try_from(generation)
                            .map_err(|_| "test generation is negative".to_string())?,
                    )
                    .ok_or_else(|| "test generation is out of range".to_string())?,
                    root_hash,
                    root_object_id: object
                        .map(|value| {
                            AsciiText::new(value)
                                .ok_or_else(|| "test root object ID is invalid".to_string())
                        })
                        .transpose()?,
                },
                lease_owner: owner
                    .map(|value| {
                        Id::new(value).ok_or_else(|| "test owner ID is invalid".to_string())
                    })
                    .transpose()?,
                lease_epoch: FenceEpoch::new(
                    u64::try_from(epoch).map_err(|_| "test epoch is negative".to_string())?,
                )
                .ok_or_else(|| "test epoch is out of range".to_string())?,
                lease_expires_at: None,
                last_transition: None,
            })
        })
}
