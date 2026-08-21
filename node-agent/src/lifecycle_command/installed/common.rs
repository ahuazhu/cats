//! Narrow shared inputs for independent installed lifecycle handlers.
//!
//! This module contains no lifecycle orchestration. Start, Suspend/Warm, and
//! Cold/Delete receive the same immutable Host coordinates and exact shared
//! admission/volume authorities; they cannot construct a second registry,
//! rescan startup, or bypass the command journal.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use cats_api::runtime_lifecycle::{
    LifecycleCommandEnvelope, LifecycleCommandResponse, VolumeTerminalReceipt,
};
use cats_api::runtime_reconciliation::Id;
use cats_storage::authority::RuntimeVolumeInventoryAuthority;

use crate::admission_registry::LifecycleAdmissionRegistry;
use crate::state_directory::StateDirectory;

use super::super::executor::LifecycleEffectAuthority;
use super::super::strong_stop::StrongStopPorts;
use super::cold_delete::AtomicColdDeletePort;
use super::start::{AtomicStartRuntimePort, AtomicStartVolumePort};
pub(crate) use super::strong_stop::StrongStopEvidence;
use super::strong_stop::{
    execute_command_strong_stop, execute_command_strong_stop_with_retained_receipts,
};
use super::suspend_warm::SuspendWarmPlatformPort;
use super::InstalledAtomicLifecycleConfig;
use super::ObservedFrontend;

#[derive(Clone)]
pub(super) struct InstalledLifecycleContext {
    config: InstalledAtomicLifecycleConfig,
    strong_stop_ports: StrongStopPorts,
    frontend_expectations: Arc<Mutex<BTreeMap<Id, Vec<ObservedFrontend>>>>,
}

impl InstalledLifecycleContext {
    pub(super) fn new(
        config: InstalledAtomicLifecycleConfig,
        strong_stop_ports: StrongStopPorts,
        frontend_expectations: Arc<Mutex<BTreeMap<Id, Vec<ObservedFrontend>>>>,
    ) -> Self {
        Self {
            config,
            strong_stop_ports,
            frontend_expectations,
        }
    }

    pub(super) fn state_directory(&self) -> &StateDirectory {
        &self.config.state_directory
    }

    pub(super) fn node_id(&self) -> &Id {
        &self.config.node_id
    }

    pub(super) fn admission_registry(&self) -> &Arc<LifecycleAdmissionRegistry> {
        &self.config.admission_registry
    }

    pub(super) fn volume_inventory_authority(&self) -> &Arc<dyn RuntimeVolumeInventoryAuthority> {
        &self.config.volume_inventory_authority
    }

    pub(super) fn start_volume_port(&self) -> &Arc<dyn AtomicStartVolumePort> {
        &self.config.start_volume_port
    }

    pub(super) fn start_runtime_port(&self) -> &Arc<dyn AtomicStartRuntimePort> {
        &self.config.start_runtime_port
    }

    pub(super) fn suspend_warm_platform(&self) -> &Arc<dyn SuspendWarmPlatformPort> {
        self.config.suspend_warm_platform.as_port()
    }

    pub(super) fn cold_delete_port(&self) -> &Arc<dyn AtomicColdDeletePort> {
        &self.config.cold_delete_port
    }

    pub(super) fn inventory_attestation_port(
        &self,
    ) -> &Arc<crate::runtime_inventory::RuntimeInventoryForceFullCoordinator> {
        &self.config.runtime_inventory_force_full
    }

    pub(super) fn execute_strong_stop(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: Option<&LifecycleCommandResponse>,
        authority: LifecycleEffectAuthority<'_>,
    ) -> Result<StrongStopEvidence> {
        execute_command_strong_stop(self, command, predecessor, authority)
    }

    pub(super) fn execute_strong_stop_with_retained_receipts(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: Option<&LifecycleCommandResponse>,
        authority: LifecycleEffectAuthority<'_>,
        verified_retained_volume_receipts: &[VolumeTerminalReceipt],
    ) -> Result<StrongStopEvidence> {
        execute_command_strong_stop_with_retained_receipts(
            self,
            command,
            predecessor,
            authority,
            Some(verified_retained_volume_receipts),
        )
    }

    pub(super) fn strong_stop_ports(&self) -> &StrongStopPorts {
        &self.strong_stop_ports
    }

    pub(super) fn frontend_expectations(&self) -> &Arc<Mutex<BTreeMap<Id, Vec<ObservedFrontend>>>> {
        &self.frontend_expectations
    }

    pub(super) fn config(&self) -> &InstalledAtomicLifecycleConfig {
        &self.config
    }
}
