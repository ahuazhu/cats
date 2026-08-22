//! Cats node agent.

pub mod admission;
pub mod admission_registry;
pub mod agent_registration;
pub(crate) mod cat_execution_scope;
pub mod ch;
pub mod guest_client;
pub mod lifecycle_command;
pub mod lifecycle_volume_client;
pub mod object_write_credential;
pub(crate) mod physical_read;
pub(crate) mod proc;
pub mod route_command;
pub mod route_grant_v2;
pub mod route_signing_rotation;
pub mod route_v2_machine;
pub mod runtime_cutover;
pub mod runtime_inventory;
pub mod semantic_installed;
pub mod semantic_lifecycle;
pub mod semantic_mounts;
pub mod semantic_node_client;
pub mod state_directory;
pub mod vmm_launcher;
