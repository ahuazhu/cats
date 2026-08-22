//! Fail-closed bridge between the semantic action lane and installed effects.
//!
//! The verified Cloud Hypervisor/blockd implementation cannot be called from
//! a [`SemanticEffectRequest`] until the semantic protocol supplies the
//! physical inputs listed by [`InstalledSemanticInput`]. The old lifecycle
//! command/journal identity is deliberately not reconstructed here.

use std::fmt;

use cats_api::runtime_reconciliation::Id;
use cats_api::semantic_control::{CatAction, SemanticErrorCode};

use crate::semantic_lifecycle::{
    SemanticActionCancellation, SemanticCatEffects, SemanticEffectError, SemanticEffectFuture,
    SemanticEffectRequest,
};

/// One physical input required by the already-verified installed leaves but
/// absent from the current semantic Node request and Node-local state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstalledSemanticInput {
    /// Root volume identity, size, remote head and current writer authority.
    RootVolumeDescriptor,
    /// Persistent volume identity, filesystem UUID, size, device slot and
    /// current writer authority for one requested product disk.
    PersistentVolumeDescriptor { disk_id: Id },
    /// Complete isolated Guest/Host network coordinates used by CH and route.
    RuntimeNetworkConfig,
    /// Current or newly allocated runtime incarnation and Guest CID.
    RuntimeIdentity,
    /// Exact source physical state needed for pause, resume, snapshot or stop.
    SourceRuntimeEvidence,
    /// Stable effect plan whose identities are fixed before Host mutation.
    PhysicalEffectPlan,
    /// Authority to converge/release each volume during Cold or destroy.
    VolumeReleaseAuthority,
    /// Admission binding needed to close/open the current unique route.
    RouteAdmissionBinding,
}

impl fmt::Display for InstalledSemanticInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootVolumeDescriptor => formatter.write_str("root_volume_descriptor"),
            Self::PersistentVolumeDescriptor { disk_id } => {
                write!(formatter, "persistent_volume_descriptor:{disk_id}")
            }
            Self::RuntimeNetworkConfig => formatter.write_str("runtime_network_config"),
            Self::RuntimeIdentity => formatter.write_str("runtime_identity"),
            Self::SourceRuntimeEvidence => formatter.write_str("source_runtime_evidence"),
            Self::PhysicalEffectPlan => formatter.write_str("physical_effect_plan"),
            Self::VolumeReleaseAuthority => formatter.write_str("volume_release_authority"),
            Self::RouteAdmissionBinding => formatter.write_str("route_admission_binding"),
        }
    }
}

/// The single typed preflight failure for the installed semantic bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledSemanticEffectsUnavailable {
    pub action: CatAction,
    pub missing: Vec<InstalledSemanticInput>,
}

impl fmt::Display for InstalledSemanticEffectsUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "installed {:?} is missing ", self.action)?;
        for (index, input) in self.missing.iter().enumerate() {
            if index > 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{input}")?;
        }
        Ok(())
    }
}

impl std::error::Error for InstalledSemanticEffectsUnavailable {}

/// Cloud Hypervisor selection for the semantic-only noded composition.
///
/// This bridge never invokes an old command runner. It rejects before the
/// first physical effect until [`preflight_installed_semantic_effect`] can be
/// satisfied from current semantic authority.
#[derive(Debug, Default)]
pub struct InstalledSemanticCatEffects;

impl InstalledSemanticCatEffects {
    pub fn new() -> Self {
        Self
    }
}

impl SemanticCatEffects for InstalledSemanticCatEffects {
    fn execute(
        &self,
        request: SemanticEffectRequest,
        cancellation: SemanticActionCancellation,
    ) -> SemanticEffectFuture {
        Box::pin(async move {
            if cancellation.is_cancelled() && request.action != CatAction::Destroy {
                return Err(SemanticEffectError::new(
                    SemanticErrorCode::ActionCancelled,
                    "installed semantic action was cancelled before preflight",
                ));
            }
            match preflight_installed_semantic_effect(&request) {
                Err(unavailable) => Err(SemanticEffectError::new(
                    SemanticErrorCode::InternalError,
                    unavailable.to_string(),
                )),
                Ok(()) => Err(SemanticEffectError::new(
                    SemanticErrorCode::InternalError,
                    "installed semantic executor is unavailable after preflight",
                )),
            }
        })
    }
}

/// Audit whether the current request can safely enter installed effects.
///
/// The function is deliberately pure. Returning `Err` proves no CH, blockd,
/// volume, Guest or route mutation has happened.
pub fn preflight_installed_semantic_effect(
    request: &SemanticEffectRequest,
) -> Result<(), InstalledSemanticEffectsUnavailable> {
    let mut missing = Vec::new();
    match request.action {
        CatAction::Create | CatAction::Run => {
            missing.extend([
                InstalledSemanticInput::RootVolumeDescriptor,
                InstalledSemanticInput::RuntimeNetworkConfig,
                InstalledSemanticInput::RuntimeIdentity,
                InstalledSemanticInput::PhysicalEffectPlan,
                InstalledSemanticInput::RouteAdmissionBinding,
            ]);
            if request.action == CatAction::Run {
                missing.push(InstalledSemanticInput::SourceRuntimeEvidence);
            }
        }
        CatAction::Suspend | CatAction::Warm => {
            missing.extend([
                InstalledSemanticInput::SourceRuntimeEvidence,
                InstalledSemanticInput::PhysicalEffectPlan,
                InstalledSemanticInput::RouteAdmissionBinding,
            ]);
        }
        CatAction::Cold | CatAction::Destroy => {
            missing.extend([
                InstalledSemanticInput::SourceRuntimeEvidence,
                InstalledSemanticInput::PhysicalEffectPlan,
                InstalledSemanticInput::VolumeReleaseAuthority,
                InstalledSemanticInput::RouteAdmissionBinding,
            ]);
        }
    }
    for mount in &request.config.mounts {
        missing.push(InstalledSemanticInput::PersistentVolumeDescriptor {
            disk_id: mount.disk_id.clone(),
        });
    }
    missing.sort();
    missing.dedup();
    Err(InstalledSemanticEffectsUnavailable {
        action: request.action,
        missing,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::semantic_lifecycle::{
        SemanticCatState, SemanticNodeService, SemanticResponseStatus,
    };
    use cats_api::runtime_reconciliation::{Id, RandomId128};
    use cats_api::semantic_control::{
        CatAction, NodedCatConfig, NodedDiskMount, PersistentDiskFormat, PersistentMountPath,
    };

    use super::*;

    fn request(action: CatAction) -> SemanticEffectRequest {
        SemanticEffectRequest {
            cat_id: "cat_01".to_owned(),
            action,
            config: NodedCatConfig {
                cpu: 2,
                memory_bytes: 4 * 1024 * 1024 * 1024,
                boot_image: "ubuntu-24.04".to_owned(),
                mounts: vec![NodedDiskMount {
                    disk_id: Id::new("disk_01").expect("disk ID"),
                    volume_id: Id::new("vol_01").expect("volume ID"),
                    filesystem_uuid: RandomId128::new("1".repeat(32)).expect("filesystem UUID"),
                    format: PersistentDiskFormat::Ext4,
                    mount_path: PersistentMountPath::new("/data").expect("mount path"),
                }],
            },
        }
    }

    #[test]
    fn running_preflight_names_every_unavailable_installed_input() {
        let error = preflight_installed_semantic_effect(&request(CatAction::Run))
            .expect_err("semantic input remains incomplete");
        assert_eq!(error.action, CatAction::Run);
        for required in [
            InstalledSemanticInput::RootVolumeDescriptor,
            InstalledSemanticInput::PersistentVolumeDescriptor {
                disk_id: Id::new("disk_01").expect("disk ID"),
            },
            InstalledSemanticInput::RuntimeNetworkConfig,
            InstalledSemanticInput::RuntimeIdentity,
            InstalledSemanticInput::SourceRuntimeEvidence,
            InstalledSemanticInput::PhysicalEffectPlan,
            InstalledSemanticInput::RouteAdmissionBinding,
        ] {
            assert!(error.missing.contains(&required), "missing {required}");
        }
    }

    #[test]
    fn destructive_preflight_requires_stop_and_volume_release_authority() {
        for action in [CatAction::Cold, CatAction::Destroy] {
            let error = preflight_installed_semantic_effect(&request(action))
                .expect_err("destructive action remains unavailable");
            assert!(error
                .missing
                .contains(&InstalledSemanticInput::SourceRuntimeEvidence));
            assert!(error
                .missing
                .contains(&InstalledSemanticInput::VolumeReleaseAuthority));
            assert!(error
                .missing
                .contains(&InstalledSemanticInput::RouteAdmissionBinding));
        }
    }

    #[tokio::test]
    async fn installed_bridge_fails_before_any_physical_effect() {
        let effects: Arc<dyn SemanticCatEffects> = Arc::new(InstalledSemanticCatEffects::new());
        let error = effects
            .execute(
                request(CatAction::Create),
                SemanticActionCancellation::new_for_test(),
            )
            .await
            .expect_err("bridge must fail closed");
        assert_eq!(error.code, SemanticErrorCode::InternalError);
        assert!(error.message.contains("root_volume_descriptor"));
        assert!(error.message.contains("route_admission_binding"));
    }

    #[tokio::test]
    async fn semantic_service_reports_installed_preflight_as_failed_not_success() {
        let service = SemanticNodeService::new(Arc::new(InstalledSemanticCatEffects::new()));
        let response = service
            .create("cat_01".to_owned(), request(CatAction::Create).config)
            .await;
        assert_eq!(response.status, SemanticResponseStatus::Failed);
        assert_eq!(response.state, Some(SemanticCatState::Failure));
        let error = response.error.expect("failed response has a typed error");
        assert_eq!(error.code, SemanticErrorCode::InternalError);
        assert!(error.message.contains("physical_effect_plan"));
    }
}
