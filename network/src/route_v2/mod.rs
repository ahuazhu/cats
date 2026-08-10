//! Production-side Route Grant v2 primitives.
//!
//! The bounded cache and verification boundary are usable now. The shipped
//! Gateway remains closed because two wire contracts are still absent from the
//! frozen specifications: the machine-authenticated Control resolve transport
//! and the Node's machine-authenticated HTTPS Route Grant v2 admission ingress.
//! This module deliberately does not infer either contract from the retired V1
//! paths.

mod cache;
mod grant;
mod http_body;

pub use cache::{
    CacheLookup, CacheRefreshStatus, CurrentRequestDisposition, NegativeRoute,
    RefreshForLaterOutcome, RefreshableRejection, RequestKind, ResolveFailure, ResolveFuture,
    RouteCache, RouteCacheConfig, RouteCacheError, RouteCacheStats, RouteResolution, RouteResolver,
};
pub use grant::{
    AuthenticatedResolveEnvelope, GrantDigest, RouteGrantKeyRing, RouteGrantKeyRingError,
    RouteGrantVerificationError, VerifiedRoute,
};
pub use http_body::{
    read_bounded_response_body, strict_https_client, ResponseBodyBounds, ResponseReadError,
};

/// A missing contract that prevents the public Gateway from opening a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionIngressSeam {
    ControlMachineResolveTransport,
    NodeV2HttpsAdmissionIngress,
}

impl std::fmt::Display for ProductionIngressSeam {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ControlMachineResolveTransport => {
                formatter.write_str("Control machine-authenticated v2 resolve transport")
            }
            Self::NodeV2HttpsAdmissionIngress => {
                formatter.write_str("Node machine-authenticated v2 HTTPS admission ingress")
            }
        }
    }
}

/// Typed fail-closed reason returned by the current production composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionIngressBlocker {
    missing: &'static [ProductionIngressSeam],
}

impl ProductionIngressBlocker {
    const MISSING: &'static [ProductionIngressSeam] = &[
        ProductionIngressSeam::ControlMachineResolveTransport,
        ProductionIngressSeam::NodeV2HttpsAdmissionIngress,
    ];

    pub const fn current() -> Self {
        Self {
            missing: Self::MISSING,
        }
    }

    pub const fn missing(self) -> &'static [ProductionIngressSeam] {
        self.missing
    }
}

impl std::fmt::Display for ProductionIngressBlocker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("missing ")?;
        for (index, seam) in self.missing.iter().enumerate() {
            if index > 0 {
                formatter.write_str(" and ")?;
            }
            seam.fmt(formatter)?;
        }
        Ok(())
    }
}

impl std::error::Error for ProductionIngressBlocker {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_blocker_names_both_unfrozen_transports() {
        let blocker = ProductionIngressBlocker::current();
        assert_eq!(
            blocker.missing(),
            &[
                ProductionIngressSeam::ControlMachineResolveTransport,
                ProductionIngressSeam::NodeV2HttpsAdmissionIngress,
            ]
        );
        let message = blocker.to_string();
        assert!(message.contains("Control machine-authenticated v2 resolve transport"));
        assert!(message.contains("Node machine-authenticated v2 HTTPS admission ingress"));
    }
}
