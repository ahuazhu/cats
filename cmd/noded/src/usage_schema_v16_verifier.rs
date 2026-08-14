//! Release-bound, read-only verifier for the exact Usage PostgreSQL v16 schema.
//!
//! The DSN is accepted only through a protected file and is never emitted in
//! argv, the environment, logs, stdout or the deterministic receipt. The
//! caller verifies this executable against the approved release manifest and
//! installation receipt before invoking it; the receipt records the digest of
//! the executable image that actually performed the verification.

mod usage_verifier_support;

use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use cats_usage_store_postgres::{
    PostgresUsageStore, USAGE_SCHEMA_V16_CATALOG_SHA256, USAGE_SCHEMA_VERSION,
};
use clap::Parser;
use serde_json::Value;

use usage_verifier_support::{
    effective_gid, effective_uid, hash_running_executable, open_protected_input, publish_receipt,
    validate_lower_hex, validate_sha256, MAX_VERIFICATION_RECEIPT_BYTES,
};

const RECEIPT_KIND: &str = "cats.usage-schema-v16-verification.v1";
const RECEIPT_VERSION: u64 = 1;
const MAX_DSN_BYTES: u64 = 16 * 1024;
const MAX_CA_BYTES: u64 = 1024 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "cats-usage-schema-v16-verifier",
    about = "Verify an existing exact Usage PostgreSQL v16 schema without mutation"
)]
struct Args {
    /// Root-owned mode-0600 file containing exactly one PostgreSQL URL.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    dsn_file: PathBuf,

    /// Root-owned PostgreSQL CA bundle. Production verification never falls
    /// back to an absent CA input.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    ca_file: PathBuf,

    /// Exact dedicated Usage schema selected by the reset plan.
    #[arg(long)]
    schema: String,

    /// Exact release commit already accepted by the reset actor.
    #[arg(long)]
    release_commit: String,

    /// Approved worker bundle digest bound by the installation receipt.
    #[arg(long)]
    worker_bundle_sha256: String,

    /// Reset-private deterministic receipt destination.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    receipt_out: PathBuf,
}

#[derive(Debug)]
struct Receipt<'a> {
    binary_sha256: &'a str,
    release_commit: &'a str,
    schema: &'a str,
    worker_bundle_sha256: &'a str,
}

impl Receipt<'_> {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut value = BTreeMap::<&str, Value>::new();
        value.insert("binary_sha256", self.binary_sha256.into());
        value.insert("catalog_sha256", USAGE_SCHEMA_V16_CATALOG_SHA256.into());
        value.insert("kind", RECEIPT_KIND.into());
        value.insert("release_commit", self.release_commit.into());
        value.insert("schema", self.schema.into());
        value.insert("schema_version", i64::from(USAGE_SCHEMA_VERSION).into());
        value.insert("verified", true.into());
        value.insert("version", RECEIPT_VERSION.into());
        value.insert("worker_bundle_sha256", self.worker_bundle_sha256.into());
        let mut bytes = serde_json::to_vec(&value).context("encode verification receipt")?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_VERIFICATION_RECEIPT_BYTES {
            bail!("verification receipt exceeds its closed byte limit");
        }
        Ok(bytes)
    }
}

fn decode_dsn(bytes: Vec<u8>) -> Result<String> {
    let mut value = String::from_utf8(bytes).context("PostgreSQL DSN file is not UTF-8")?;
    if value.ends_with('\n') {
        value.pop();
    }
    if value.is_empty()
        || value.ends_with('\r')
        || value.contains(['\r', '\n'])
        || value.trim() != value
    {
        bail!("PostgreSQL DSN file must contain exactly one non-empty canonical line");
    }
    Ok(value)
}

fn clear_postgres_environment() {
    let names: Vec<_> = env::vars_os()
        .filter_map(|(name, _value)| {
            let name_bytes = name.as_encoded_bytes();
            (name_bytes == b"DATABASE_URL" || name_bytes.starts_with(b"PG")).then_some(name)
        })
        .collect();
    for name in names {
        env::remove_var(name);
    }
}

fn run(args: Args) -> Result<()> {
    if effective_uid() != 0 || effective_gid() != 0 {
        bail!("verification must run with root credentials");
    }
    validate_lower_hex(&args.release_commit, 40, "release commit")?;
    validate_sha256(&args.worker_bundle_sha256, "worker bundle digest")?;

    let dsn = decode_dsn(
        open_protected_input(
            &args.dsn_file,
            MAX_DSN_BYTES,
            &[0o600],
            "PostgreSQL DSN file",
        )?
        .read_bounded(MAX_DSN_BYTES, "PostgreSQL DSN file")?,
    )?;
    let ca_input = open_protected_input(
        &args.ca_file,
        MAX_CA_BYTES,
        &[0o600, 0o644],
        "PostgreSQL CA file",
    )?;

    let binary_sha256 = hash_running_executable()?;
    validate_sha256(&binary_sha256, "running executable digest")?;
    clear_postgres_environment();

    #[cfg(target_os = "linux")]
    let ca_path = ca_input.proc_fd_path();
    #[cfg(not(target_os = "linux"))]
    let ca_path = args
        .ca_file
        .to_str()
        .context("PostgreSQL CA path is not UTF-8")?
        .to_string();

    // Keep `ca_input` alive while the adapter re-opens its pinned procfs
    // descriptor. On non-Linux development hosts it still pins and validates
    // the original file around the adapter call.
    let _keep_ca_open = &ca_input;
    PostgresUsageStore::verify_existing_schema_v16(&dsn, Some(&ca_path), &args.schema)
        .map_err(|_error| anyhow::anyhow!("Usage schema verification failed closed"))?;

    let bytes = Receipt {
        binary_sha256: &binary_sha256,
        release_commit: &args.release_commit,
        schema: &args.schema,
        worker_bundle_sha256: &args.worker_bundle_sha256,
    }
    .canonical_bytes()?;
    publish_receipt(&args.receipt_out, &bytes)
}

fn main() {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(_error) => {
            eprintln!("Usage schema v16 verification failed closed");
            std::process::exit(1);
        }
    };
    match run(args) {
        Ok(()) => println!("Usage schema v16 verified"),
        Err(_error) => {
            eprintln!("Usage schema v16 verification failed closed");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn receipt_shape_and_bytes_are_frozen() {
        let bytes = Receipt {
            binary_sha256: SHA,
            release_commit: "0123456789abcdef0123456789abcdef01234567",
            schema: "cats_usage_fresh",
            worker_bundle_sha256: SHA,
        }
        .canonical_bytes()
        .unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            concat!(
                "{\"binary_sha256\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",",
                "\"catalog_sha256\":\"sha256:ec10b4afe112dba411466e9b2d67d1cef5d8d232da4ec52c11ced993d771f157\",",
                "\"kind\":\"cats.usage-schema-v16-verification.v1\",",
                "\"release_commit\":\"0123456789abcdef0123456789abcdef01234567\",",
                "\"schema\":\"cats_usage_fresh\",\"schema_version\":16,\"verified\":true,\"version\":1,",
                "\"worker_bundle_sha256\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}\n"
            )
        );
    }

    #[test]
    fn dsn_decoder_accepts_one_optional_lf_and_rejects_ambiguous_lines() {
        assert_eq!(
            decode_dsn(b"postgresql://cats:secret@example/cats?sslmode=verify-full\n".to_vec())
                .unwrap(),
            "postgresql://cats:secret@example/cats?sslmode=verify-full"
        );
        for invalid in [
            b"".as_slice(),
            b"\n".as_slice(),
            b" postgresql://example/cats".as_slice(),
            b"postgresql://example/cats\nsecond".as_slice(),
            b"postgresql://example/cats\r\n".as_slice(),
        ] {
            assert!(decode_dsn(invalid.to_vec()).is_err());
        }
    }

    #[test]
    fn release_identifiers_are_canonical_lowercase_only() {
        assert!(
            validate_lower_hex("0123456789abcdef0123456789abcdef01234567", 40, "commit").is_ok()
        );
        assert!(
            validate_lower_hex("0123456789ABCDEF0123456789abcdef01234567", 40, "commit").is_err()
        );
        assert!(validate_sha256(SHA, "digest").is_ok());
        assert!(validate_sha256(&SHA[7..], "digest").is_err());
    }
}
