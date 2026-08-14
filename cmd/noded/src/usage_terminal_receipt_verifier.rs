//! Offline verifier for one canonical Usage target-terminal receipt.
//!
//! This is the only reset-side implementation of the Rust terminal receipt
//! semantics. The Python reset executor verifies the installed executable,
//! invokes this boundary and consumes its deterministic non-secret receipt; it
//! does not duplicate the nested Usage authority rules.

mod usage_verifier_support;

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use cats_metering::{
    validate_target_terminal_receipt, UsageTargetTerminalReceipt, UsageTargetTerminalRequest,
};
use clap::Parser;
use serde_json::Value;
use sha2::{Digest, Sha256};

use usage_verifier_support::{
    effective_gid, effective_uid, hash_running_executable, open_protected_input, publish_receipt,
    validate_lower_hex, validate_sha256, MAX_VERIFICATION_RECEIPT_BYTES,
};

const RECEIPT_KIND: &str = "cats.usage-terminal-receipt-verification.v1";
const RECEIPT_VERSION: u64 = 1;
const MAX_INPUT_BYTES: u64 = 1024 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "cats-usage-terminal-receipt-verifier",
    about = "Verify one canonical Usage target-terminal receipt offline"
)]
struct Args {
    /// Root-owned canonical usage-target-terminal-receipt.json.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    receipt_file: PathBuf,

    /// Root-owned canonical request journal sent to begin/complete.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    expected_request_file: PathBuf,

    /// Exact qualified release commit.
    #[arg(long)]
    release_commit: String,

    /// Approved worker bundle digest bound by the installation receipt.
    #[arg(long)]
    worker_bundle_sha256: String,

    /// Reset-private deterministic verification receipt destination.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    receipt_out: PathBuf,
}

#[derive(Debug)]
struct VerificationReceipt<'a> {
    binary_sha256: &'a str,
    expected_request_file_sha256: &'a str,
    release_commit: &'a str,
    target_receipt_file_sha256: &'a str,
    target_request_sha256: &'a str,
    worker_bundle_sha256: &'a str,
}

impl VerificationReceipt<'_> {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut value = BTreeMap::<&str, Value>::new();
        value.insert("binary_sha256", self.binary_sha256.into());
        value.insert(
            "expected_request_file_sha256",
            self.expected_request_file_sha256.into(),
        );
        value.insert("kind", RECEIPT_KIND.into());
        value.insert("release_commit", self.release_commit.into());
        value.insert(
            "target_receipt_file_sha256",
            self.target_receipt_file_sha256.into(),
        );
        value.insert("target_request_sha256", self.target_request_sha256.into());
        value.insert("validated", true.into());
        value.insert("version", RECEIPT_VERSION.into());
        value.insert("worker_bundle_sha256", self.worker_bundle_sha256.into());
        let mut bytes =
            serde_json::to_vec(&value).context("encode terminal verification receipt")?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_VERIFICATION_RECEIPT_BYTES {
            bail!("terminal verification receipt exceeds its closed byte limit");
        }
        Ok(bytes)
    }
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn decode_canonical_value(bytes: &[u8], description: &str) -> Result<Value> {
    let value: Value =
        serde_json::from_slice(bytes).with_context(|| format!("decode canonical {description}"))?;
    let mut canonical =
        serde_json::to_vec(&value).with_context(|| format!("encode canonical {description}"))?;
    canonical.push(b'\n');
    if canonical != bytes {
        bail!("{description} is not compact key-sorted JSON with one trailing LF");
    }
    Ok(value)
}

fn validate_release_binding(
    request: &UsageTargetTerminalRequest,
    release_commit: &str,
    worker_bundle_sha256: &str,
) -> Result<()> {
    let bundle_hex = worker_bundle_sha256
        .strip_prefix("sha256:")
        .context("worker bundle digest lacks sha256 prefix")?;
    if request.release_commit != release_commit || request.artifact_sha256 != bundle_hex {
        bail!("target terminal request is bound to a different release artifact");
    }
    Ok(())
}

fn validate_inputs(
    receipt: &UsageTargetTerminalReceipt,
    expected_request: &UsageTargetTerminalRequest,
    release_commit: &str,
    worker_bundle_sha256: &str,
) -> Result<()> {
    validate_target_terminal_receipt(receipt)
        .map_err(|_error| anyhow::anyhow!("Usage target terminal receipt is invalid"))?;
    if receipt.request != *expected_request {
        bail!("Usage target terminal receipt does not bind the expected request journal");
    }
    validate_release_binding(&receipt.request, release_commit, worker_bundle_sha256)
}

fn run(args: Args) -> Result<()> {
    if effective_uid() != 0 || effective_gid() != 0 {
        bail!("verification must run with root credentials");
    }
    validate_lower_hex(&args.release_commit, 40, "release commit")?;
    validate_sha256(&args.worker_bundle_sha256, "worker bundle digest")?;

    let receipt_bytes = open_protected_input(
        &args.receipt_file,
        MAX_INPUT_BYTES,
        &[0o400, 0o600],
        "Usage target terminal receipt",
    )?
    .read_bounded(MAX_INPUT_BYTES, "Usage target terminal receipt")?;
    let request_bytes = open_protected_input(
        &args.expected_request_file,
        MAX_INPUT_BYTES,
        &[0o400, 0o600],
        "Usage target terminal request",
    )?
    .read_bounded(MAX_INPUT_BYTES, "Usage target terminal request")?;

    let receipt_value = decode_canonical_value(&receipt_bytes, "Usage target terminal receipt")?;
    let request_value = decode_canonical_value(&request_bytes, "Usage target terminal request")?;
    let receipt: UsageTargetTerminalReceipt = serde_json::from_value(receipt_value)
        .context("decode typed Usage target terminal receipt")?;
    let expected_request: UsageTargetTerminalRequest = serde_json::from_value(request_value)
        .context("decode typed Usage target terminal request")?;

    validate_inputs(
        &receipt,
        &expected_request,
        &args.release_commit,
        &args.worker_bundle_sha256,
    )?;

    let binary_sha256 = hash_running_executable()?;
    let expected_request_file_sha256 = sha256_prefixed(&request_bytes);
    let target_receipt_file_sha256 = sha256_prefixed(&receipt_bytes);
    let verification = VerificationReceipt {
        binary_sha256: &binary_sha256,
        expected_request_file_sha256: &expected_request_file_sha256,
        release_commit: &args.release_commit,
        target_receipt_file_sha256: &target_receipt_file_sha256,
        target_request_sha256: &receipt.request_sha256,
        worker_bundle_sha256: &args.worker_bundle_sha256,
    }
    .canonical_bytes()?;
    publish_receipt(&args.receipt_out, &verification)
}

fn main() {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(_error) => {
            eprintln!("Usage terminal receipt verification failed closed");
            std::process::exit(1);
        }
    };
    match run(args) {
        Ok(()) => println!("Usage terminal receipt verified"),
        Err(_error) => {
            eprintln!("Usage terminal receipt verification failed closed");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_reconciliation::RandomId128;
    use cats_metering::{
        sha256_prefixed as metering_sha256, target_terminal_marker, target_terminal_request_sha256,
        UsageArchiveEvidence, UsageTargetBinding, UsageTerminalBarrierProjection,
        UsageTerminalShardTarget,
    };

    const SHA: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn verification_receipt_shape_and_bytes_are_frozen() {
        let bytes = VerificationReceipt {
            binary_sha256: SHA,
            expected_request_file_sha256: SHA,
            release_commit: "0123456789abcdef0123456789abcdef01234567",
            target_receipt_file_sha256: SHA,
            target_request_sha256: SHA,
            worker_bundle_sha256: SHA,
        }
        .canonical_bytes()
        .unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            concat!(
                "{\"binary_sha256\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",",
                "\"expected_request_file_sha256\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",",
                "\"kind\":\"cats.usage-terminal-receipt-verification.v1\",",
                "\"release_commit\":\"0123456789abcdef0123456789abcdef01234567\",",
                "\"target_receipt_file_sha256\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",",
                "\"target_request_sha256\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",",
                "\"validated\":true,\"version\":1,",
                "\"worker_bundle_sha256\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}\n"
            )
        );
    }

    #[test]
    fn canonical_input_requires_sorted_compact_bytes_and_one_lf() {
        assert_eq!(
            decode_canonical_value(b"{\"a\":1,\"b\":2}\n", "fixture").unwrap(),
            serde_json::json!({"a": 1, "b": 2})
        );
        for invalid in [
            b"{\"b\":2,\"a\":1}\n".as_slice(),
            b"{ \"a\":1,\"b\":2}\n".as_slice(),
            b"{\"a\":1,\"b\":2}".as_slice(),
            b"{\"a\":1,\"b\":2}\n\n".as_slice(),
        ] {
            assert!(decode_canonical_value(invalid, "fixture").is_err());
        }
    }

    fn target(name: &str) -> UsageTargetBinding {
        UsageTargetBinding {
            aws_account_id: "123456789012".into(),
            aws_region: "us-east-1".into(),
            usage_schema: format!("cats_usage_{name}"),
            stream_name: format!("usage-{name}"),
            stream_arn: format!("arn:aws:kinesis:us-east-1:123456789012:stream/usage-{name}"),
            checkpoint_table_name: format!("usage-{name}-checkpoints"),
            checkpoint_table_arn: format!(
                "arn:aws:dynamodb:us-east-1:123456789012:table/usage-{name}-checkpoints"
            ),
            archive_bucket_name: format!("usage-{name}-archive"),
            archive_bucket_arn: format!("arn:aws:s3:::usage-{name}-archive"),
        }
    }

    fn valid_pair() -> (UsageTargetTerminalRequest, UsageTargetTerminalReceipt) {
        let sources = Vec::new();
        let request = UsageTargetTerminalRequest {
            contract_version: 1,
            terminal_epoch_id: RandomId128::new("11111111111111111111111111111111").unwrap(),
            release_commit: "0123456789abcdef0123456789abcdef01234567".into(),
            artifact_sha256: SHA.strip_prefix("sha256:").unwrap().into(),
            created_at_unix_ms: 1_000,
            old_target: target("old"),
            fresh_target: target("fresh"),
            source_set_sha256: metering_sha256(&serde_json::to_vec(&sources).unwrap()),
            sources,
            shards: vec![UsageTerminalShardTarget {
                shard_id: "shardId-000000000000".into(),
                explicit_hash_key: "0".into(),
            }],
        };
        let request_sha256 = target_terminal_request_sha256(&request).unwrap();
        let marker = target_terminal_marker(&request, "shardId-000000000000").unwrap();
        let receipt = UsageTargetTerminalReceipt {
            contract_version: 1,
            request: request.clone(),
            request_sha256,
            source_receipts: Vec::new(),
            barriers: vec![UsageTerminalBarrierProjection {
                marker,
                archive: UsageArchiveEvidence {
                    stream_name: "usage-old".into(),
                    archive_bucket: "usage-old-archive".into(),
                    shard_id: "shardId-000000000000".into(),
                    sequence_number: "42".into(),
                    archive_key: "terminal/v1/marker.json".into(),
                    archive_sha256: SHA.into(),
                },
            }],
        };
        (request, receipt)
    }

    #[test]
    fn rust_validator_and_external_request_and_release_binding_are_all_required() {
        let (request, receipt) = valid_pair();
        validate_inputs(
            &receipt,
            &request,
            "0123456789abcdef0123456789abcdef01234567",
            SHA,
        )
        .unwrap();

        let mut foreign_request = request.clone();
        foreign_request.created_at_unix_ms += 1;
        assert!(validate_inputs(
            &receipt,
            &foreign_request,
            "0123456789abcdef0123456789abcdef01234567",
            SHA,
        )
        .is_err());
        assert!(validate_inputs(
            &receipt,
            &request,
            "1123456789abcdef0123456789abcdef01234567",
            SHA,
        )
        .is_err());

        let mut corrupt = receipt;
        corrupt.barriers[0].archive.sequence_number = "043".into();
        assert!(validate_inputs(
            &corrupt,
            &request,
            "0123456789abcdef0123456789abcdef01234567",
            SHA,
        )
        .is_err());
    }
}
