use std::{fs, path::PathBuf, process::ExitCode};

use cats_qualification_protocol::{
    catalog_sha256, event_record_sha256, observation_record_sha256, terminal_record_sha256,
    validate_catalog, validate_coverage_ledger, validate_trial_record, Catalog, CoverageLedger,
    TrialRecord,
};
use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;

#[derive(Debug, Parser)]
#[command(name = "cats-qualification-protocol")]
#[command(about = "Validate Cats qualification protocol documents without executing scenarios")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Catalog {
        path: PathBuf,
    },
    Trial {
        catalog: PathBuf,
        record: PathBuf,
    },
    Coverage {
        catalog: PathBuf,
        plan: PathBuf,
        ledger: PathBuf,
        #[arg(long = "trial", value_name = "PATH")]
        trials: Vec<PathBuf>,
    },
    CatalogDigest {
        path: PathBuf,
    },
    RecordDigests {
        record: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("invalid: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::Catalog { path } => {
            let catalog: Catalog = read_json(&path)?;
            validate_catalog(&catalog).map_err(|error| error.to_string())?;
            Ok(format!("valid catalog: {} cases", catalog.cases.len()))
        }
        Command::Trial { catalog, record } => {
            let catalog_bytes = fs::read(&catalog)
                .map_err(|error| format!("failed to read {}: {error}", catalog.display()))?;
            let catalog: Catalog = serde_json::from_slice(&catalog_bytes)
                .map_err(|error| format!("failed to parse {}: {error}", catalog.display()))?;
            let trial: TrialRecord = read_json(&record)?;
            validate_trial_record(&trial, &catalog, &catalog_sha256(&catalog_bytes))
                .map_err(|error| error.to_string())?;
            Ok(format!("valid trial: {}", trial.trial_id))
        }
        Command::Coverage {
            catalog,
            plan,
            ledger,
            trials,
        } => {
            let catalog_bytes = fs::read(&catalog)
                .map_err(|error| format!("failed to read {}: {error}", catalog.display()))?;
            let catalog: Catalog = serde_json::from_slice(&catalog_bytes)
                .map_err(|error| format!("failed to parse {}: {error}", catalog.display()))?;
            let ledger: CoverageLedger = read_json(&ledger)?;
            let plan_bytes = fs::read(&plan)
                .map_err(|error| format!("failed to read {}: {error}", plan.display()))?;
            let trial_bytes: Vec<Vec<u8>> = trials
                .iter()
                .map(|path| {
                    fs::read(path)
                        .map_err(|error| format!("failed to read {}: {error}", path.display()))
                })
                .collect::<Result<_, _>>()?;
            let trial_documents: Vec<&[u8]> = trial_bytes.iter().map(Vec::as_slice).collect();
            validate_coverage_ledger(
                &ledger,
                &catalog,
                &catalog_sha256(&catalog_bytes),
                &plan_bytes,
                &trial_documents,
            )
            .map_err(|error| error.to_string())?;
            Ok(format!(
                "valid {:?} coverage: {} entries",
                ledger.phase,
                ledger.entries.len()
            ))
        }
        Command::CatalogDigest { path } => {
            let bytes = fs::read(&path)
                .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
            let catalog: Catalog = serde_json::from_slice(&bytes)
                .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
            validate_catalog(&catalog).map_err(|error| error.to_string())?;
            Ok(catalog_sha256(&bytes))
        }
        Command::RecordDigests { record } => {
            let trial: TrialRecord = read_json(&record)?;
            let mut lines = Vec::with_capacity(trial.events.len() + 2);
            for event in &trial.events {
                lines.push(format!(
                    "event\t{}\t{}",
                    event.event_id,
                    event_record_sha256(event).map_err(|error| error.to_string())?
                ));
            }
            lines.push(format!(
                "observation\t{}\t{}",
                trial.observation.observation_id,
                observation_record_sha256(&trial.observation).map_err(|error| error.to_string())?
            ));
            lines.push(format!(
                "terminal\t{}\t{}",
                trial.terminal.terminal_id,
                terminal_record_sha256(&trial.terminal).map_err(|error| error.to_string())?
            ));
            Ok(lines.join("\n"))
        }
    }
}

fn read_json<T: DeserializeOwned>(path: &PathBuf) -> Result<T, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))
}
