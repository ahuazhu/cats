use std::process::ExitCode;

const CUTOVER_BLOCKER: &str = "cats-gatewayd is intentionally unavailable: Route Grant v2 is not composed; production ingress remains fail-closed";

fn main() -> ExitCode {
    eprintln!("{CUTOVER_BLOCKER}");
    ExitCode::FAILURE
}
