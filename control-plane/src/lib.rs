//! Cats control plane: Resource API, operations, scheduler and controllers.

pub mod api;
pub mod auth;
pub mod billing;
pub(crate) mod gateway_machine;
pub mod object_write_gateway;
pub(crate) mod route_grant_v2;
pub(crate) mod route_rotation_machine;
pub mod server;
pub mod store;
#[doc(hidden)]
pub mod testsupport;
pub mod ui;
