//! Versioned claims carried by a control-plane signed Endpoint Route Grant.
//!
//! This crate owns only the wire shape. Private-key signing belongs to the
//! control plane and public-key verification belongs to the Node agent; the
//! Gateway deliberately treats the compact JWS as opaque (ADR-0033).

use serde::{Deserialize, Serialize};

pub const ROUTE_GRANT_VERSION: u8 = 1;
pub const ROUTE_GRANT_ISSUER: &str = "cats-control-plane";
pub const ROUTE_GRANT_AUDIENCE: &str = "cats-node-agent";
pub const DEFAULT_ROUTE_GRANT_TTL_SECONDS: u64 = 120;
pub const MAX_ROUTE_GRANT_TTL_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantClaims {
    pub version: u8,
    pub iss: String,
    pub aud: String,
    pub hostname: String,
    pub workspace_id: String,
    pub cat_id: String,
    pub cat_generation: i64,
    pub node_id: String,
    pub route_epoch: i64,
    pub target_port: u16,
    pub iat: u64,
    pub exp: u64,
}
