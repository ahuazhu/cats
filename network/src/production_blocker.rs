/// A missing contract that prevents the public Gateway from opening a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionIngressSeam {
    GatewayWorkloadIdentityAuthority,
    RouteV2KeyDistributionComposition,
    ControlMachineTransportComposition,
    PublicProxyListenerComposition,
}

impl std::fmt::Display for ProductionIngressSeam {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GatewayWorkloadIdentityAuthority => {
                formatter.write_str("Gateway workload credential and policy authority")
            }
            Self::RouteV2KeyDistributionComposition => {
                formatter.write_str("Route v2 signer and Node key-ring distribution")
            }
            Self::ControlMachineTransportComposition => {
                formatter.write_str("Control machine-authenticated resolve transport")
            }
            Self::PublicProxyListenerComposition => {
                formatter.write_str("public ingress proxy/listener composition")
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
        ProductionIngressSeam::GatewayWorkloadIdentityAuthority,
        ProductionIngressSeam::RouteV2KeyDistributionComposition,
        ProductionIngressSeam::ControlMachineTransportComposition,
        ProductionIngressSeam::PublicProxyListenerComposition,
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
    fn production_blocker_names_all_unimplemented_wires_and_composition() {
        let blocker = ProductionIngressBlocker::current();
        assert_eq!(
            blocker.missing(),
            &[
                ProductionIngressSeam::GatewayWorkloadIdentityAuthority,
                ProductionIngressSeam::RouteV2KeyDistributionComposition,
                ProductionIngressSeam::ControlMachineTransportComposition,
                ProductionIngressSeam::PublicProxyListenerComposition,
            ]
        );
        assert_eq!(
            blocker.to_string(),
            "missing Gateway workload credential and policy authority and Route v2 signer and Node key-ring distribution and Control machine-authenticated resolve transport and public ingress proxy/listener composition"
        );
    }
}
