use std::{fs, io::Read, path::PathBuf, process::ExitCode};

use cats_rc_source_chain::{verify_source_chain, SourceChainRecord, VerificationContext};
use clap::{Parser, Subcommand};

const MAX_RECORD_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "cats-rc-source-chain")]
#[command(about = "Validate one trusted RC source-chain edge")]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Verify {
        #[arg(long)]
        record: PathBuf,
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
        #[arg(long)]
        expected_repository: String,
        #[arg(long, default_value = "refs/heads/rc/architecture-v2")]
        rc_ref: String,
        #[arg(long, default_value = "rc/architecture-v2")]
        rc_branch: String,
        #[arg(long)]
        controller_sha: String,
        #[arg(long)]
        expected_before_sha: String,
        #[arg(long)]
        expected_after_sha: String,
        #[arg(long)]
        trusted_main_head_sha: String,
        #[arg(long = "required-check", required = true)]
        required_checks: Vec<String>,
    },
}

fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rc source-chain rejected: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    match arguments.command {
        Command::Verify {
            record,
            repository_root,
            expected_repository,
            rc_ref,
            rc_branch,
            controller_sha,
            expected_before_sha,
            expected_after_sha,
            trusted_main_head_sha,
            required_checks,
        } => {
            let file = fs::File::open(&record)?;
            if file.metadata()?.len() > MAX_RECORD_BYTES {
                return Err("source-chain record exceeds the 1 MiB input limit".into());
            }
            let mut bytes = Vec::new();
            file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_RECORD_BYTES {
                return Err("source-chain record exceeds the 1 MiB input limit".into());
            }
            let record: SourceChainRecord = serde_json::from_slice(&bytes)?;
            let required_checks = required_checks
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let verdict = verify_source_chain(
                &record,
                &VerificationContext {
                    repository_root: &repository_root,
                    expected_repository: &expected_repository,
                    expected_rc_ref: &rc_ref,
                    expected_rc_branch: &rc_branch,
                    expected_controller_sha: &controller_sha,
                    expected_before_sha: &expected_before_sha,
                    expected_after_sha: &expected_after_sha,
                    trusted_main_head_sha: &trusted_main_head_sha,
                    expected_required_checks: &required_checks,
                },
            )?;
            println!("{}", serde_json::to_string(&verdict)?);
        }
    }
    Ok(())
}
