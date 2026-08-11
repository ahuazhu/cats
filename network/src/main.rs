use std::process::ExitCode;

mod production_blocker;
pub use production_blocker::{ProductionIngressBlocker, ProductionIngressSeam};

const CUTOVER_PREFIX: &str =
    "cats-gatewayd is intentionally unavailable: Route Grant v2 is not composed";

fn main() -> ExitCode {
    let blocker = ProductionIngressBlocker::current();
    eprintln!("{CUTOVER_PREFIX}: {blocker}; production ingress remains fail-closed");
    ExitCode::FAILURE
}
