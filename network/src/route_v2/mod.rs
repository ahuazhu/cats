//! Production-side opaque Route Grant v2 transport primitives.
//!
//! Gateway never parses Grant claims or owns a public-key ring; Node is the sole
//! Grant verifier and final admission authority. This module composes the
//! machine-authenticated Control resolver, bounded local cache, public HTTP/WS
//! byte proxy, and authenticated Node tunnel without any retired V1 fallback.

mod cache;
mod control_resolver;
mod grant;
mod http_body;
mod ingress;
mod node_machine;

pub use cache::{
    CacheLookup, CacheRefreshStatus, CurrentRequestDisposition, NegativeRoute,
    RefreshForLaterOutcome, RefreshableRejection, RequestKind, ResolveFailure, ResolveFuture,
    RouteCache, RouteCacheConfig, RouteCacheError, RouteCacheStats, RouteResolution, RouteResolver,
};
pub use control_resolver::{ControlMachineTarget, ControlRouteResolver, ControlRouteResolverError};
pub use grant::{AuthenticatedResolveEnvelope, GrantDigest, ResolveEnvelopeError, ResolvedRoute};
pub use http_body::{
    read_bounded_response_body, strict_https_client, ResponseBodyBounds, ResponseReadError,
};
pub use ingress::{
    BoxedGatewayTunnel, GatewayIngress, GatewayIngressConfig, GatewayIngressError, GatewayTunnel,
    TunnelConnector, TunnelFuture,
};
pub use node_machine::{GatewayNodeRouteTunnel, GatewayNodeRouteV2Client, GatewayNodeRouteV2Error};
