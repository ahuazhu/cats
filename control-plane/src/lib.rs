//! Cats control plane: Resource API, operations, scheduler and controllers.

pub mod api;
pub mod auth;
pub mod billing;
pub mod object_write_gateway;
pub mod semantic_adapters;
pub mod semantic_disk;
pub mod semantic_lifecycle;
pub mod semantic_node;
pub mod semantic_node_recovery;
pub mod semantic_noded_client;
pub mod semantic_resource_service;
pub mod semantic_strict_disk_backend;
pub mod server;
pub mod store;
#[doc(hidden)]
pub mod testsupport;
pub mod ui;
