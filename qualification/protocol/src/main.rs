use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
};

use cats_qualification_protocol::{
    catalog_sha256, event_record_sha256, observation_record_sha256, terminal_record_sha256,
    validate_catalog, validate_coverage_ledger, validate_final_qualification,
    validate_trial_record, AuthorityTrustAnchors, Catalog, CoverageLedger, FinalQualification,
    PhaseDocuments, TrialDocument, TrialRecord, ED25519_PUBLIC_KEY_BYTES,
    MAX_APPEND_RECEIPTS_DOCUMENT_BYTES, MAX_AUTHORITY_DOCUMENT_BYTES, MAX_CATALOG_DOCUMENT_BYTES,
    MAX_COVERAGE_DOCUMENT_BYTES, MAX_FINAL_DOCUMENT_BYTES, MAX_TRIAL_DOCUMENTS,
    MAX_TRIAL_DOCUMENT_BYTES, MAX_TRIAL_PLAN_DOCUMENT_BYTES,
};
use clap::{Args, Parser, Subcommand};
use serde::de::DeserializeOwned;

#[derive(Debug, Parser)]
#[command(name = "cats-qualification-protocol")]
#[command(about = "Validate Cats qualification protocol documents without executing scenarios")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct TrustArgs {
    #[arg(long)]
    actor_authority_public_key: PathBuf,
    #[arg(long)]
    append_ledger_public_key: PathBuf,
    #[arg(long, default_value = "qualification-actor-authority-v1")]
    actor_authority_key_id: String,
    #[arg(long, default_value = "qualification-append-ledger-v1")]
    append_ledger_key_id: String,
}

#[derive(Debug, Subcommand)]
enum Command {
    Catalog {
        path: PathBuf,
    },
    Trial {
        catalog: PathBuf,
        record: PathBuf,
        #[arg(long)]
        actor_authority: PathBuf,
        #[arg(long)]
        append_receipts: PathBuf,
        #[command(flatten)]
        trust: TrustArgs,
    },
    Coverage {
        catalog: PathBuf,
        plan: PathBuf,
        ledger: PathBuf,
        #[arg(long)]
        actor_authority: PathBuf,
        #[arg(long = "trial", value_name = "PATH")]
        trials: Vec<PathBuf>,
        #[arg(long = "append-receipts", value_name = "PATH")]
        append_receipts: Vec<PathBuf>,
        #[command(flatten)]
        trust: TrustArgs,
    },
    Final {
        catalog: PathBuf,
        record: PathBuf,
        #[arg(long)]
        functional_ledger: PathBuf,
        #[arg(long)]
        functional_plan: PathBuf,
        #[arg(long)]
        functional_actor_authority: PathBuf,
        #[arg(long = "functional-trial", value_name = "PATH")]
        functional_trials: Vec<PathBuf>,
        #[arg(long = "functional-append-receipts", value_name = "PATH")]
        functional_append_receipts: Vec<PathBuf>,
        #[arg(long)]
        aws_performance_ledger: PathBuf,
        #[arg(long)]
        aws_performance_plan: PathBuf,
        #[arg(long)]
        aws_performance_actor_authority: PathBuf,
        #[arg(long = "aws-performance-trial", value_name = "PATH")]
        aws_performance_trials: Vec<PathBuf>,
        #[arg(long = "aws-performance-append-receipts", value_name = "PATH")]
        aws_performance_append_receipts: Vec<PathBuf>,
        #[command(flatten)]
        trust: TrustArgs,
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
            let catalog: Catalog =
                read_json_bounded(&path, MAX_CATALOG_DOCUMENT_BYTES, "catalog document")?;
            validate_catalog(&catalog).map_err(|error| error.to_string())?;
            Ok(format!("valid catalog: {} cases", catalog.cases.len()))
        }
        Command::Trial {
            catalog,
            record,
            actor_authority,
            append_receipts,
            trust,
        } => {
            let (catalog_bytes, catalog) = read_catalog(&catalog)?;
            let trial: TrialRecord =
                read_json_bounded(&record, MAX_TRIAL_DOCUMENT_BYTES, "trial document")?;
            let authority_bytes = read_bounded(
                &actor_authority,
                MAX_AUTHORITY_DOCUMENT_BYTES,
                "actor authority manifest",
            )?;
            let append_bytes = read_bounded(
                &append_receipts,
                MAX_APPEND_RECEIPTS_DOCUMENT_BYTES,
                "append receipt bundle",
            )?;
            let keys = LoadedTrust::load(&trust)?;
            validate_trial_record(
                &trial,
                &catalog,
                &catalog_sha256(&catalog_bytes),
                &authority_bytes,
                &append_bytes,
                &keys.anchors(&trust),
            )
            .map_err(|error| error.to_string())?;
            Ok(format!("valid trial: {}", trial.trial_id))
        }
        Command::Coverage {
            catalog,
            plan,
            ledger,
            actor_authority,
            trials,
            append_receipts,
            trust,
        } => {
            let (catalog_bytes, catalog) = read_catalog(&catalog)?;
            let ledger: CoverageLedger =
                read_json_bounded(&ledger, MAX_COVERAGE_DOCUMENT_BYTES, "coverage ledger")?;
            let plan_bytes = read_bounded(&plan, MAX_TRIAL_PLAN_DOCUMENT_BYTES, "trial plan")?;
            let authority_bytes = read_bounded(
                &actor_authority,
                MAX_AUTHORITY_DOCUMENT_BYTES,
                "actor authority manifest",
            )?;
            let loaded = load_trials(&trials, &append_receipts)?;
            let documents = loaded.documents();
            let keys = LoadedTrust::load(&trust)?;
            validate_coverage_ledger(
                &ledger,
                &catalog,
                &catalog_sha256(&catalog_bytes),
                &plan_bytes,
                &documents,
                &authority_bytes,
                &keys.anchors(&trust),
            )
            .map_err(|error| error.to_string())?;
            Ok(format!(
                "valid {:?} coverage: {} entries",
                ledger.phase,
                ledger.entries.len()
            ))
        }
        Command::Final {
            catalog,
            record,
            functional_ledger,
            functional_plan,
            functional_actor_authority,
            functional_trials,
            functional_append_receipts,
            aws_performance_ledger,
            aws_performance_plan,
            aws_performance_actor_authority,
            aws_performance_trials,
            aws_performance_append_receipts,
            trust,
        } => {
            let (catalog_bytes, catalog) = read_catalog(&catalog)?;
            let final_record: FinalQualification = read_json_bounded(
                &record,
                MAX_FINAL_DOCUMENT_BYTES,
                "final qualification document",
            )?;
            let functional = LoadedPhase::load(
                &functional_ledger,
                &functional_plan,
                &functional_actor_authority,
                &functional_trials,
                &functional_append_receipts,
            )?;
            let aws = LoadedPhase::load(
                &aws_performance_ledger,
                &aws_performance_plan,
                &aws_performance_actor_authority,
                &aws_performance_trials,
                &aws_performance_append_receipts,
            )?;
            let functional_documents = functional.trials.documents();
            let aws_documents = aws.trials.documents();
            let functional_input = functional.documents(&functional_documents);
            let aws_input = aws.documents(&aws_documents);
            let keys = LoadedTrust::load(&trust)?;
            validate_final_qualification(
                &final_record,
                &catalog,
                &catalog_sha256(&catalog_bytes),
                &functional_input,
                &aws_input,
                &keys.anchors(&trust),
            )
            .map_err(|error| error.to_string())?;
            Ok(format!(
                "valid final qualification composition: {:?}",
                final_record.outcome
            ))
        }
        Command::CatalogDigest { path } => {
            let bytes = read_bounded(&path, MAX_CATALOG_DOCUMENT_BYTES, "catalog document")?;
            let catalog: Catalog = parse_json(&path, &bytes)?;
            validate_catalog(&catalog).map_err(|error| error.to_string())?;
            Ok(catalog_sha256(&bytes))
        }
        Command::RecordDigests { record } => {
            let trial: TrialRecord =
                read_json_bounded(&record, MAX_TRIAL_DOCUMENT_BYTES, "trial document")?;
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

fn read_catalog(path: &Path) -> Result<(Vec<u8>, Catalog), String> {
    let bytes = read_bounded(path, MAX_CATALOG_DOCUMENT_BYTES, "catalog document")?;
    let catalog = parse_json(path, &bytes)?;
    Ok((bytes, catalog))
}

fn read_json_bounded<T: DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<T, String> {
    let bytes = read_bounded(path, max_bytes, label)?;
    parse_json(path, &bytes)
}

fn parse_json<T: DeserializeOwned>(path: &Path, bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))
}

fn read_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let file =
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to stat {}: {error}", path.display()))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "{label} exceeds {max_bytes} bytes before allocation"
        ));
    }
    let capacity = usize::try_from(metadata.len().min(max_bytes)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes while reading"));
    }
    Ok(bytes)
}

struct LoadedTrust {
    actor_public_key: Vec<u8>,
    append_public_key: Vec<u8>,
}

impl LoadedTrust {
    fn load(args: &TrustArgs) -> Result<Self, String> {
        let actor_public_key = read_bounded(
            &args.actor_authority_public_key,
            ED25519_PUBLIC_KEY_BYTES as u64,
            "actor authority public key",
        )?;
        let append_public_key = read_bounded(
            &args.append_ledger_public_key,
            ED25519_PUBLIC_KEY_BYTES as u64,
            "append ledger public key",
        )?;
        if actor_public_key.len() != ED25519_PUBLIC_KEY_BYTES
            || append_public_key.len() != ED25519_PUBLIC_KEY_BYTES
        {
            return Err(format!(
                "Ed25519 public keys must be exactly {ED25519_PUBLIC_KEY_BYTES} bytes"
            ));
        }
        Ok(Self {
            actor_public_key,
            append_public_key,
        })
    }

    fn anchors<'a>(&'a self, args: &'a TrustArgs) -> AuthorityTrustAnchors<'a> {
        AuthorityTrustAnchors {
            actor_authority_key_id: &args.actor_authority_key_id,
            actor_authority_public_key: &self.actor_public_key,
            append_ledger_key_id: &args.append_ledger_key_id,
            append_ledger_public_key: &self.append_public_key,
        }
    }
}

struct LoadedTrials {
    trials: Vec<Vec<u8>>,
    append_receipts: Vec<Vec<u8>>,
}

impl LoadedTrials {
    fn documents(&self) -> Vec<TrialDocument<'_>> {
        self.trials
            .iter()
            .zip(&self.append_receipts)
            .map(|(trial, receipts)| TrialDocument {
                trial_bytes: trial,
                append_receipts_bytes: receipts,
            })
            .collect()
    }
}

fn load_trials(trials: &[PathBuf], append_receipts: &[PathBuf]) -> Result<LoadedTrials, String> {
    require_trial_path_counts(trials.len(), append_receipts.len())?;
    let trials = trials
        .iter()
        .map(|path| read_bounded(path, MAX_TRIAL_DOCUMENT_BYTES, "trial document"))
        .collect::<Result<Vec<_>, _>>()?;
    let append_receipts = append_receipts
        .iter()
        .map(|path| {
            read_bounded(
                path,
                MAX_APPEND_RECEIPTS_DOCUMENT_BYTES,
                "append receipt bundle",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LoadedTrials {
        trials,
        append_receipts,
    })
}

fn require_trial_path_counts(trials: usize, receipts: usize) -> Result<(), String> {
    if trials > MAX_TRIAL_DOCUMENTS {
        return Err(format!(
            "trial path count exceeds protocol cap {MAX_TRIAL_DOCUMENTS}"
        ));
    }
    if trials != receipts {
        return Err("every trial path needs one append-receipts path".to_owned());
    }
    Ok(())
}

struct LoadedPhase {
    ledger: Vec<u8>,
    plan: Vec<u8>,
    actor_authority: Vec<u8>,
    trials: LoadedTrials,
}

impl LoadedPhase {
    fn load(
        ledger: &Path,
        plan: &Path,
        actor_authority: &Path,
        trials: &[PathBuf],
        append_receipts: &[PathBuf],
    ) -> Result<Self, String> {
        Ok(Self {
            ledger: read_bounded(ledger, MAX_COVERAGE_DOCUMENT_BYTES, "coverage ledger")?,
            plan: read_bounded(plan, MAX_TRIAL_PLAN_DOCUMENT_BYTES, "trial plan")?,
            actor_authority: read_bounded(
                actor_authority,
                MAX_AUTHORITY_DOCUMENT_BYTES,
                "actor authority manifest",
            )?,
            trials: load_trials(trials, append_receipts)?,
        })
    }

    fn documents<'a>(&'a self, trials: &'a [TrialDocument<'a>]) -> PhaseDocuments<'a> {
        PhaseDocuments {
            coverage_ledger_bytes: &self.ledger,
            trial_plan_bytes: &self.plan,
            actor_authority_manifest_bytes: &self.actor_authority,
            trial_documents: trials,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_file_is_rejected_before_body_allocation() {
        let path = std::env::temp_dir().join(format!(
            "cats-qualification-limit-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(&path, [0_u8; 16]).expect("exact-limit probe file");
        assert_eq!(
            read_bounded(&path, 16, "probe").expect("exact-limit file must pass"),
            [0_u8; 16]
        );
        std::fs::write(&path, [0_u8; 17]).expect("temporary probe file");
        let error = read_bounded(&path, 16, "probe").expect_err("oversized file must fail");
        std::fs::remove_file(path).expect("remove temporary probe file");
        assert!(error.contains("before allocation"));
    }

    #[test]
    fn excessive_or_unpaired_trial_paths_fail_before_reads() {
        assert!(require_trial_path_counts(MAX_TRIAL_DOCUMENTS + 1, 0)
            .expect_err("excessive paths")
            .contains("protocol cap"));
        assert!(require_trial_path_counts(1, 0)
            .expect_err("unpaired path")
            .contains("one append-receipts"));
    }
}
