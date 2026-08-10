use std::process::ExitCode;

const CUTOVER_PREFIX: &str =
    "cats-gatewayd is intentionally unavailable: Route Grant v2 is not composed";

fn main() -> ExitCode {
    let blocker = cats_network::route_v2::ProductionIngressBlocker::current();
    eprintln!("{CUTOVER_PREFIX}: {blocker}; production ingress remains fail-closed");
    ExitCode::FAILURE
}
