use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "cats-route-v2-node-r1-validator",
    about = "Validate one closed Node Route v2 revision-1 artifact transaction"
)]
struct Arguments {
    /// Absolute root-owned 0700 directory containing exactly four artifacts.
    #[arg(long)]
    directory: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let artifacts =
        cats_api::runtime_artifacts::load_initial_node_route_v2_machine_artifact_candidate(
            &arguments.directory,
        )
        .context("load closed Node Route v2 revision-1 artifact transaction")?;
    cats_node_agent::route_v2_machine::validate_initial_node_route_v2_machine_artifacts(&artifacts)
        .context("validate Node Route v2 revision-1 ring and TLS transaction")
}
