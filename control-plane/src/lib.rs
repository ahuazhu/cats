//! Cats control plane: Resource API, operations, scheduler and controllers.

pub mod api;
pub mod auth;
pub mod billing;
pub(crate) mod gateway_machine;
pub mod object_write_gateway;
pub(crate) mod route_grant_v2;
pub(crate) mod route_rotation_machine;
pub mod semantic_disk;
pub mod semantic_lifecycle;
pub mod semantic_noded_client;
pub mod semantic_node;
pub mod server;
pub mod store;
#[doc(hidden)]
pub mod testsupport;
pub mod ui;
