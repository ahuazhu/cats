//! Signed Control + exact local-lineage adapter for atomic Start Volume grants.
//!
//! Control owns the writer transition and immutable replay ledger. This
//! adapter then revalidates every returned receipt against one fresh complete
//! Volume-authority snapshot and joins it to the deterministic local lineage.
//! The canonical typed authority receipt and planned lineage path are handed
//! to the physical Start platform. Neither value is, or can stand in for, a
//! blockd token, frontend capability, or object-write credential.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cats_api::runtime_lifecycle::{
    CommandFailureReason, LifecycleCommand, LifecycleCommandEnvelope, VolumeTerminalReceipt,
};
use cats_api::runtime_lifecycle_volume as wire;
use cats_api::runtime_reconciliation::{
    AcquireOrigin, ContractVersion, HostPath, LastVolumeTransition, RemoteHead, SessionBinding,
    UnixMillis, WireU64,
};
use cats_storage::authority::{
    validate_volume_owner_binding, validate_volume_record, AttachmentLineageIdentity,
    NodeVolumeInventoryRecord, RuntimeVolumeInventoryAuthority,
};
use cats_storage::lifecycle_volume::{
    command_start_volume_grant_receipt_digest_for_current_owner, LifecycleVolumeCommandScope,
};

use crate::admission_registry::LifecycleAdmissionRegistry;
use crate::lifecycle_volume_client::LifecycleVolumeHttpClient;
use crate::state_directory::StateDirectory;

use super::cold_delete::inspect_lineage_durability_read_only;
use super::start::{
    begin_start_volume_lease_request, publish_start_volume_lease_witness,
    AtomicStartDefiniteFailure, AtomicStartVolumeAction, AtomicStartVolumeBatchReceipt,
    AtomicStartVolumeBatchRequest, AtomicStartVolumeFailureEvidence, AtomicStartVolumeGrant,
    AtomicStartVolumeOutcome, AtomicStartVolumePort,
};

/// Production writer-authority half of atomic Start.
pub struct InstalledAtomicStartVolumePort {
    state_directory: StateDirectory,
    inventory_authority: Arc<dyn RuntimeVolumeInventoryAuthority>,
    control: Arc<LifecycleVolumeHttpClient>,
    admission_registry: Arc<LifecycleAdmissionRegistry>,
    configured_lease_duration_ms: WireU64,
    control_request_timeout: Duration,
}

impl std::fmt::Debug for InstalledAtomicStartVolumePort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledAtomicStartVolumePort")
            .field("state_directory", &self.state_directory)
            .field(
                "configured_lease_duration_ms",
                &self.configured_lease_duration_ms,
            )
            .field("control_request_timeout", &self.control_request_timeout)
            .finish_non_exhaustive()
    }
}

impl InstalledAtomicStartVolumePort {
    pub fn new(
        state_directory: StateDirectory,
        inventory_authority: Arc<dyn RuntimeVolumeInventoryAuthority>,
        control: Arc<LifecycleVolumeHttpClient>,
        admission_registry: Arc<LifecycleAdmissionRegistry>,
        configured_lease_duration: Duration,
        control_request_timeout: Duration,
    ) -> Result<Arc<Self>> {
        let configured_lease_duration_ms = u64::try_from(configured_lease_duration.as_millis())
            .context("atomic Start Volume lease duration overflows u64")?;
        anyhow::ensure!(
            (1..=i64::MAX as u64).contains(&configured_lease_duration_ms)
                && !control_request_timeout.is_zero(),
            "atomic Start Volume lease/control timeout is invalid"
        );
        Ok(Arc::new(Self {
            state_directory,
            inventory_authority,
            control,
            admission_registry,
            configured_lease_duration_ms: WireU64::new(configured_lease_duration_ms)
                .context("atomic Start Volume lease duration is outside the wire domain")?,
            control_request_timeout,
        }))
    }

    fn apply_or_replay(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartVolumeBatchRequest,
        planned_agent_session: &SessionBinding,
    ) -> Result<AtomicStartVolumeOutcome> {
        let LifecycleCommand::Start(spec) = &command.command else {
            anyhow::bail!("atomic Start Volume port received another command kind")
        };
        anyhow::ensure!(
            request.version == ContractVersion::V1
                && request.operation_id == command.operation_id
                && request.request_fingerprint == command.request_fingerprint
                && request.cat_id == command.cat_id
                && request.node_id == command.node_id
                && request.placement_identity == command.placement_identity
                && request.actions.len() == command.runtime_config.volumes.len()
                && request
                    .actions
                    .iter()
                    .zip(&command.runtime_config.volumes)
                    .all(|(action, volume)| action_volume(action) == volume),
            "atomic Start Volume durable request does not bind its command"
        );
        let now = current_unix_millis()?;
        if now >= spec.effect_deadline_unix_ms {
            return Ok(definite_authority_failure(
                CommandFailureReason::InvalidLocalPrecondition,
                AtomicStartVolumeFailureEvidence::local_deadline_elapsed(command, request)?,
            ));
        }
        let session = self
            .admission_registry
            .current_agent_session()
            .context("read current AgentSession for atomic Start Volume transition")?;
        anyhow::ensure!(
            session.node_id == command.node_id,
            "current AgentSession belongs to another Node"
        );
        let scope = wire_scope(command);
        let batch = wire::LifecycleStartVolumeBatch {
            scope: scope.clone(),
            grant_sequence: request.grant_sequence,
            renewal_lease_duration_ms: request.renewal_lease_duration_ms,
            actions: request.actions.iter().cloned().map(wire_action).collect(),
        };
        let transition = wire::LifecycleVolumeTransitionRequest {
            version: ContractVersion::V1,
            session: session.clone(),
            transition: wire::LifecycleVolumeTransitionRequestKind::StartVolumes {
                batch: Box::new(batch),
            },
        };
        let wall_remaining =
            Duration::from_millis(spec.effect_deadline_unix_ms.get().saturating_sub(now.get()));
        let budget = self.control_request_timeout.min(wall_remaining);
        if budget.is_zero() {
            return Ok(definite_authority_failure(
                CommandFailureReason::InvalidLocalPrecondition,
                AtomicStartVolumeFailureEvidence::local_deadline_elapsed(command, request)?,
            ));
        }
        let deadline = Instant::now()
            .checked_add(budget)
            .context("atomic Start Volume Control deadline overflow")?;
        let request_started_at =
            begin_start_volume_lease_request(request, planned_agent_session, &session)?;
        let response = self
            .control
            .transition(&transition, deadline)
            .context("submit exact atomic Start Volume transition")?;
        anyhow::ensure!(
            self.admission_registry.current_agent_session()? == session,
            "AgentSession changed during atomic Start Volume transition"
        );
        let applied = match &response.result {
            wire::LifecycleVolumeTransitionResult::Applied { applied } => applied.clone(),
            wire::LifecycleVolumeTransitionResult::Rejected {
                reason:
                    wire::LifecycleVolumeTransitionRejection::AuthorityRejected
                    | wire::LifecycleVolumeTransitionRejection::TakeoverUnavailable,
            } => {
                return Ok(definite_authority_failure(
                    CommandFailureReason::VolumeAuthorityRejected,
                    AtomicStartVolumeFailureEvidence::control_rejected(
                        command, request, &response,
                    )?,
                ))
            }
            wire::LifecycleVolumeTransitionResult::Rejected { reason } => {
                anyhow::bail!(
                    "atomic Start Volume transition remains unresolved after Control rejection {reason:?}"
                )
            }
        };
        let wire::LifecycleVolumeTransitionApplied::StartVolumesReady {
            grant_sequence,
            grants,
        } = applied
        else {
            anyhow::bail!("atomic Start Volume transition returned another result kind")
        };
        anyhow::ensure!(
            grant_sequence == request.grant_sequence && grants.len() == request.actions.len(),
            "atomic Start Volume response changed its grant round or set"
        );
        let outcome = self.join_grants(command, request, &scope, grants)?;
        if let AtomicStartVolumeOutcome::Ready(receipt) = &outcome {
            publish_start_volume_lease_witness(
                request,
                receipt,
                planned_agent_session,
                request_started_at,
            )?;
        }
        Ok(outcome)
    }

    fn join_grants(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartVolumeBatchRequest,
        wire_scope: &wire::LifecycleVolumeCommandScope,
        grants: Vec<wire::LifecycleStoredStartVolumeGrant>,
    ) -> Result<AtomicStartVolumeOutcome> {
        let candidates = request
            .actions
            .iter()
            .map(|action| action_volume(action).volume_id.clone())
            .collect::<BTreeSet<_>>();
        let snapshot = self
            .inventory_authority
            .load_node_volume_inventory(&command.node_id, &candidates)
            .context("reload exact atomic Start Volume authority snapshot")?;
        anyhow::ensure!(
            snapshot.node_id == command.node_id,
            "atomic Start Volume snapshot belongs to another Node"
        );
        let mut rows = BTreeMap::new();
        for row in snapshot.records {
            validate_volume_record(&row.volume)
                .context("validate atomic Start Volume authority row")?;
            if let Some(binding) = &row.binding {
                validate_volume_owner_binding(binding, &row.volume)
                    .context("validate atomic Start Volume owner binding")?;
            }
            anyhow::ensure!(
                rows.insert(row.volume.volume_id.clone(), row).is_none(),
                "atomic Start Volume snapshot repeats a Volume"
            );
        }
        anyhow::ensure!(
            candidates.iter().all(|volume| rows.contains_key(volume)),
            "atomic Start Volume snapshot omitted a candidate"
        );
        let storage_scope = storage_scope(wire_scope);
        let mut installed = Vec::with_capacity(grants.len());
        for (stored, action) in grants.into_iter().zip(&request.actions) {
            let config = action_volume(action);
            anyhow::ensure!(
                stored.receipt.volume == *config
                    && stored.receipt.grant_sequence == request.grant_sequence,
                "atomic Start Volume receipt changed its config or grant sequence"
            );
            let row = rows
                .get(&config.volume_id)
                .context("atomic Start Volume receipt lacks its current authority row")?;
            let current_digest = command_start_volume_grant_receipt_digest_for_current_owner(
                &storage_scope,
                request.grant_sequence,
                config,
                &row.volume,
                &stored.receipt,
            )
            .context("revalidate immutable atomic Start grant receipt")?;
            anyhow::ensure!(
                current_digest == stored.receipt_digest,
                "atomic Start grant receipt digest differs from Control ledger"
            );
            installed.push(self.join_one_grant(command, action, row, stored)?);
        }
        anyhow::ensure!(
            installed
                .windows(2)
                .all(|pair| pair[0].volume.volume_id < pair[1].volume.volume_id),
            "atomic Start Volume grants are not strictly sorted"
        );
        Ok(AtomicStartVolumeOutcome::Ready(
            AtomicStartVolumeBatchReceipt {
                grant_sequence: request.grant_sequence,
                grants: installed,
            },
        ))
    }

    fn join_one_grant(
        &self,
        command: &LifecycleCommandEnvelope,
        action: &AtomicStartVolumeAction,
        row: &NodeVolumeInventoryRecord,
        stored: wire::LifecycleStoredStartVolumeGrant,
    ) -> Result<AtomicStartVolumeGrant> {
        let (attachment_id, attachment_epoch, _, _, acquire_origin) =
            grant_authority(&stored.receipt, &row.volume)?;
        let binding = row
            .binding
            .as_ref()
            .context("atomic Start grant current Volume is Unowned")?;
        anyhow::ensure!(
            binding.owner_node_id == command.node_id
                && binding.attachment_id == attachment_id
                && binding.attachment_epoch == attachment_epoch,
            "atomic Start grant does not own its fresh exact Volume row"
        );
        // The immutable command receipt is a lower bound. A serving blockd
        // may publish a later head or renew the same attachment after the
        // Control transaction commits but before this fresh snapshot. The
        // storage validator above proved that this row is that monotonic
        // successor, so physical planning must consume the fresh row rather
        // than boot or resume from the stale receipt head.
        let authoritative_head = row.volume.head.clone();
        let lease_expires_at = row
            .volume
            .lease_expires_at
            .context("atomic Start current owner lacks a lease expiry")?;
        match action {
            AtomicStartVolumeAction::NormalAcquire {
                requested_attachment_id,
                ..
            }
            | AtomicStartVolumeAction::RenewSameNode {
                attachment_id: requested_attachment_id,
                ..
            } => anyhow::ensure!(
                requested_attachment_id == &attachment_id,
                "atomic Start grant changed its requested attachment"
            ),
            AtomicStartVolumeAction::Takeover {
                authorization_id, ..
            } => anyhow::ensure!(
                acquire_origin
                    == (AcquireOrigin::Takeover {
                        authorization_id: authorization_id.clone(),
                    }),
                "atomic Start takeover grant changed its authorization"
            ),
        }
        let lineage = AttachmentLineageIdentity {
            volume_id: stored.receipt.volume.volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch,
            acquire_origin: acquire_origin.clone(),
            node_id: command.node_id.clone(),
            placement_epoch: command.placement_identity.placement_epoch,
        };
        let (lineage_path, lineage_host_path) = lineage_path(
            &self.state_directory,
            &command.cat_id,
            &stored.receipt.volume.volume_id,
            &attachment_id,
            attachment_epoch.get(),
        )?;
        let local_durable_generation = match fs::symlink_metadata(&lineage_path) {
            Ok(_) => {
                let (local, _) = inspect_lineage_durability_read_only(
                    &lineage_path,
                    &lineage,
                    &authoritative_head,
                )
                .context("inspect exact atomic Start local lineage")?;
                local
            }
            Err(error)
                if error.kind() == ErrorKind::NotFound
                    && grant_allows_unmaterialized_lineage(command, &stored.receipt) =>
            {
                authoritative_head.generation
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                anyhow::bail!("same-Node atomic Start local lineage is absent")
            }
            Err(error) => return Err(error).context("inspect atomic Start lineage path"),
        };
        let terminal = VolumeTerminalReceipt {
            volume_id: stored.receipt.volume.volume_id.clone(),
            disk_id: stored.receipt.volume.disk_id.clone(),
            disk_role: stored.receipt.volume.disk_role,
            attachment_id,
            attachment_epoch,
            local_durable_generation,
            remote_durable_generation: authoritative_head.generation,
            authority_receipt_digest: Some(stored.receipt_digest.clone()),
        };
        Ok(AtomicStartVolumeGrant::new(
            terminal,
            acquire_origin,
            authoritative_head,
            lease_expires_at,
            stored.receipt_digest,
            stored.receipt,
            lineage_host_path,
        ))
    }
}

fn grant_allows_unmaterialized_lineage(
    command: &LifecycleCommandEnvelope,
    receipt: &wire::LifecycleCommandStartVolumeGrantReceipt,
) -> bool {
    match &receipt.authority {
        wire::LifecycleStartVolumeGrantAuthority::NormalAcquire { .. } => true,
        wire::LifecycleStartVolumeGrantAuthority::RenewSameNode {
            expected_source,
            serving_acquire,
            ..
        } => {
            receipt.grant_sequence.get() > 0
                && matches!(
                    serving_acquire.as_ref(),
                    wire::LifecycleServingAcquire::Normal { .. }
                )
                && expected_source
                    == &(cats_api::runtime_reconciliation::VolumeTransitionSource::Lifecycle {
                        operation_id: command.operation_id.clone(),
                        request_fingerprint: command.request_fingerprint.clone(),
                    })
        }
    }
}

impl AtomicStartVolumePort for InstalledAtomicStartVolumePort {
    fn configured_lease_duration_ms(&self) -> WireU64 {
        self.configured_lease_duration_ms
    }

    fn current_agent_session_binding(&self) -> Result<SessionBinding> {
        Ok(self.admission_registry.current_agent_session()?)
    }

    fn inspect_or_apply_start_volumes(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartVolumeBatchRequest,
        planned_agent_session: &SessionBinding,
    ) -> Result<AtomicStartVolumeOutcome> {
        self.apply_or_replay(command, request, planned_agent_session)
    }
}

fn definite_authority_failure(
    reason: CommandFailureReason,
    evidence: AtomicStartVolumeFailureEvidence,
) -> AtomicStartVolumeOutcome {
    AtomicStartVolumeOutcome::Failed {
        failure: Box::new(AtomicStartDefiniteFailure {
            reason,
            artifact_classifications: Vec::new(),
            runtime_progress: None,
        }),
        evidence: Box::new(evidence),
    }
}

fn wire_scope(command: &LifecycleCommandEnvelope) -> wire::LifecycleVolumeCommandScope {
    wire::LifecycleVolumeCommandScope {
        operation_id: command.operation_id.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        cat_id: command.cat_id.clone(),
        node_id: command.node_id.clone(),
        placement_identity: command.placement_identity.clone(),
    }
}

fn storage_scope(scope: &wire::LifecycleVolumeCommandScope) -> LifecycleVolumeCommandScope {
    LifecycleVolumeCommandScope {
        operation_id: scope.operation_id.clone(),
        request_fingerprint: scope.request_fingerprint.clone(),
        cat_id: scope.cat_id.clone(),
        node_id: scope.node_id.clone(),
        placement_identity: scope.placement_identity.clone(),
    }
}

fn wire_action(action: AtomicStartVolumeAction) -> wire::LifecycleStartVolumeAction {
    match action {
        AtomicStartVolumeAction::NormalAcquire {
            volume,
            expected_unowned_epoch,
            transition_id,
            requested_attachment_id,
            lease_duration_ms,
        } => wire::LifecycleStartVolumeAction::NormalAcquire {
            volume,
            expected_unowned_epoch,
            transition_id,
            requested_attachment_id,
            lease_duration_ms,
        },
        AtomicStartVolumeAction::RenewSameNode {
            volume,
            attachment_id,
            attachment_epoch,
            lease_duration_ms,
        } => wire::LifecycleStartVolumeAction::RenewSameNode {
            volume,
            attachment_id,
            attachment_epoch,
            lease_duration_ms,
        },
        AtomicStartVolumeAction::Takeover {
            volume,
            authorization_id,
        } => wire::LifecycleStartVolumeAction::Takeover {
            volume,
            authorization_id,
        },
    }
}

fn action_volume(
    action: &AtomicStartVolumeAction,
) -> &cats_api::runtime_lifecycle::RuntimeVolumeConfig {
    match action {
        AtomicStartVolumeAction::NormalAcquire { volume, .. }
        | AtomicStartVolumeAction::RenewSameNode { volume, .. }
        | AtomicStartVolumeAction::Takeover { volume, .. } => volume,
    }
}

fn grant_authority(
    receipt: &wire::LifecycleCommandStartVolumeGrantReceipt,
    current: &cats_api::runtime_reconciliation::VolumeRecord,
) -> Result<(
    cats_api::runtime_reconciliation::Id,
    cats_api::runtime_reconciliation::FenceEpoch,
    RemoteHead,
    UnixMillis,
    AcquireOrigin,
)> {
    match &receipt.authority {
        wire::LifecycleStartVolumeGrantAuthority::NormalAcquire { request, result } => Ok((
            result.attachment_id.clone(),
            result.resulting_epoch,
            result.resulting_head.clone(),
            result.lease_expires_at,
            AcquireOrigin::Normal {
                transition_id: request.transition_id.clone(),
            },
        )),
        wire::LifecycleStartVolumeGrantAuthority::RenewSameNode { result, .. } => Ok((
            result.attachment_id.clone(),
            result.epoch,
            result.resulting_head.clone(),
            result.lease_expires_at,
            current_acquire_origin(current)?,
        )),
    }
}

fn current_acquire_origin(
    current: &cats_api::runtime_reconciliation::VolumeRecord,
) -> Result<AcquireOrigin> {
    match current.last_transition.as_ref() {
        Some(LastVolumeTransition::NormalAcquire { request, .. }) => Ok(AcquireOrigin::Normal {
            transition_id: request.transition_id.clone(),
        }),
        Some(LastVolumeTransition::Takeover {
            authorization_id, ..
        }) => Ok(AcquireOrigin::Takeover {
            authorization_id: authorization_id.clone(),
        }),
        _ => anyhow::bail!("atomic Start renewal current row lost its acquire lineage"),
    }
}

fn lineage_path(
    state_directory: &StateDirectory,
    cat_id: &cats_api::runtime_reconciliation::Id,
    volume_id: &cats_api::runtime_reconciliation::Id,
    attachment_id: &cats_api::runtime_reconciliation::Id,
    attachment_epoch: u64,
) -> Result<(PathBuf, HostPath)> {
    let path = state_directory
        .path()
        .join("data")
        .join(format!("cat-{cat_id}"))
        .join(format!("volume-{volume_id}"))
        .join(format!("attachment-{attachment_id}"))
        .join(format!("epoch-{attachment_epoch}"));
    anyhow::ensure!(
        path.is_absolute(),
        "atomic Start lineage path is not absolute"
    );
    let wire = HostPath::new(
        path.to_str()
            .context("atomic Start lineage path is not UTF-8")?
            .to_owned(),
    )
    .context("atomic Start lineage path exceeds the HostPath contract")?;
    Ok((path, wire))
}

fn current_unix_millis() -> Result<UnixMillis> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Host wall clock precedes Unix epoch")?;
    let millis = u64::try_from(duration.as_millis()).context("Host wall clock overflows u64")?;
    UnixMillis::new(millis).context("Host wall clock is outside the lifecycle wire domain")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_lineage_path_retains_full_attachment_identity() {
        let state = StateDirectory::unanchored(PathBuf::from("/var/lib/cats/node"));
        let cat_id = cats_api::runtime_reconciliation::Id::new("cat-1").unwrap();
        let (path, wire) = lineage_path(
            &state,
            &cat_id,
            &cats_api::runtime_reconciliation::Id::new("volume-1").unwrap(),
            &cats_api::runtime_reconciliation::Id::new("attachment-1").unwrap(),
            7,
        )
        .unwrap();
        assert_eq!(
            path,
            Path::new(
                "/var/lib/cats/node/data/cat-cat-1/volume-volume-1/attachment-attachment-1/epoch-7"
            )
        );
        assert_eq!(wire.as_str(), path.to_str().unwrap());
    }
}
