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

/// Compose the production Control resolver and Node tunnel client with the
/// shared test Gateway leaf. This exists only for cross-crate vertical tests;
/// production always reads the one fixed installed artifact set.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn gateway_machine_clients_for_test(
    control_target: ControlMachineTarget,
) -> anyhow::Result<(RouteResolver, GatewayNodeRouteV2Client)> {
    const CA_CERTIFICATE: &[u8] =
        include_bytes!("../../../control-plane/tests/fixtures/gateway_machine_ca_certificate.pem");
    const CLIENT_CERTIFICATE: &[u8] = include_bytes!(
        "../../../control-plane/tests/fixtures/gateway_machine_client_certificate.pem"
    );
    const CLIENT_PRIVATE_KEY: &[u8] = include_bytes!(
        "../../../control-plane/tests/fixtures/gateway_machine_client_private_key.pem"
    );

    let resolver = ControlRouteResolver::from_pem_for_test(
        control_target,
        CA_CERTIFICATE,
        CLIENT_CERTIFICATE,
        CLIENT_PRIVATE_KEY,
    )?
    .into_route_resolver();
    let node_client = GatewayNodeRouteV2Client::from_pem_for_test(
        CA_CERTIFICATE,
        CLIENT_CERTIFICATE,
        CLIENT_PRIVATE_KEY,
    )?;
    Ok((resolver, node_client))
}
