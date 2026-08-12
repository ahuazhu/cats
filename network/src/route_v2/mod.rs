//! Production-side opaque Route Grant v2 transport primitives.
//!
//! The bounded cache and authenticated-envelope validation boundary are usable
//! now. Gateway never parses Grant claims or owns a public-key ring; Node is the
//! sole Grant verifier and final admission authority. The shipped Gateway stays
//! closed until the Gateway workload identity authority, independent v2 key
//! distribution, machine-authenticated Control composition, and public
//! proxy/listener composition are complete. The Node machine tunnel is now a
//! production primitive, but the shipped public Gateway remains closed. This
//! module does not infer identity from the retired V1 paths.

mod cache;
mod grant;
mod http_body;
mod node_machine;

pub use crate::production_blocker::{ProductionIngressBlocker, ProductionIngressSeam};
pub use cache::{
    CacheLookup, CacheRefreshStatus, CurrentRequestDisposition, NegativeRoute,
    RefreshForLaterOutcome, RefreshableRejection, RequestKind, ResolveFailure, ResolveFuture,
    RouteCache, RouteCacheConfig, RouteCacheError, RouteCacheStats, RouteResolution, RouteResolver,
};
pub use grant::{AuthenticatedResolveEnvelope, GrantDigest, ResolveEnvelopeError, ResolvedRoute};
pub use http_body::{
    read_bounded_response_body, strict_https_client, ResponseBodyBounds, ResponseReadError,
};
pub use node_machine::{GatewayNodeRouteTunnel, GatewayNodeRouteV2Client, GatewayNodeRouteV2Error};
