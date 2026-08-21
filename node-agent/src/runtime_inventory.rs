//! Independent signed runtime inventory and telemetry sender.
//!
//! This module observes physical state and the sole lifecycle command journal.
//! It never reads Desired state, executes a physical effect, opens Route
//! admission, or settles a lifecycle Operation.  Full and Partial reports use
//! one crash-safe sequence journal and an independent owned runner, so a scan
//! or telemetry transport failure cannot starve lifecycle command polling.

mod attestation;
mod installed_vmm;
mod journal;
mod runner;
mod startup;

pub use attestation::{
    RuntimeInventoryAttestationPort, RuntimeInventoryForceFullCoordinator,
    RuntimeInventoryForceFullError,
};
pub(crate) use installed_vmm::{inspect_installed_vmm_api, InstalledVmmApiInspection};
pub use journal::{RuntimeInventoryJournal, RuntimeInventoryJournalError};
pub(crate) use runner::observed_command_journal_record;
pub use runner::{
    observed_command_journal, ProductionRuntimeInventorySource, RuntimeFullInventoryFuture,
    RuntimeFullInventoryScan, RuntimeInventoryCollectionError, RuntimeInventoryCollectionPort,
    RuntimeInventoryHttpClient, RuntimeInventoryReadiness, RuntimeInventoryRunner,
    RuntimeInventoryRunnerError, RuntimeInventorySource, RuntimeInventoryTransport,
    RuntimeInventoryTransportAttempt, RuntimeInventoryTransportFuture,
    RuntimeInventoryTransportRetryReason, RuntimePartialInventoryContext,
    RuntimePartialInventoryFuture, RuntimePartialInventoryScan,
};
pub use startup::{StartupInventoryCache, StartupInventoryCacheError};
