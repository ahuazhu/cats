//! Authorized SQLite block server for the legacy NodeRuntime behavior tests.
//!
//! The production daemon deliberately accepts no unsigned legacy serving
//! mode. These tests still need a real, killable NBD process while they
//! characterize restart adoption, lifecycle ordering, and ledger writes, so
//! this explicit example translates their frozen legacy argv into a complete
//! externally installed test authorization.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;

use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse};
use cats_blockd::engine::{ChunkEngine, DurabilityMode, EngineConfig};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_file::FileBlobStore;
use cats_storage::authority::VolumeDurability;
use cats_storage::{MetaError, MetadataStore as _};
use cats_test_support::{prepare_sqlite_authorized_serving, SqliteTestVolumeGrant};

const TEST_VOLUME_SIZE_ENV: &str = "CATS_TEST_BLOCKD_VOLUME_SIZE_BYTES";
const TEST_ATTACHMENT_EPOCH_ENV: &str = "CATS_TEST_BLOCKD_ATTACHMENT_EPOCH";

#[derive(Default)]
struct LegacyRuntimeArgs {
    volume_id: Option<String>,
    data_dir: Option<PathBuf>,
    attachment_id: Option<String>,
    metadata_adapter: Option<String>,
    object_adapter: Option<String>,
    nbd_socket: Option<PathBuf>,
    control_socket: Option<PathBuf>,
    lease_ttl_ms: Option<i64>,
    max_staged_bytes: Option<u64>,
    max_staged_packs: Option<usize>,
    max_local_bytes: Option<u64>,
    metadata_path: Option<PathBuf>,
    blob_root: Option<PathBuf>,
    durability: Option<String>,
}

impl LegacyRuntimeArgs {
    fn parse() -> Self {
        let mut parsed = Self::default();
        let mut arguments = std::env::args_os().skip(1);
        while let Some(argument) = arguments.next() {
            let flag = argument.to_string_lossy();
            match flag.as_ref() {
                "--volume-id" => {
                    parsed.volume_id = Some(utf8(next_value(&mut arguments, &flag), &flag));
                }
                "--data-dir" => {
                    parsed.data_dir = Some(next_value(&mut arguments, &flag).into());
                }
                "--attachment-id" => {
                    parsed.attachment_id = Some(utf8(next_value(&mut arguments, &flag), &flag));
                }
                "--metadata-store-adapter" => {
                    parsed.metadata_adapter = Some(utf8(next_value(&mut arguments, &flag), &flag));
                }
                "--object-store-adapter" => {
                    parsed.object_adapter = Some(utf8(next_value(&mut arguments, &flag), &flag));
                }
                "--listen-unix" => {
                    parsed.nbd_socket = Some(next_value(&mut arguments, &flag).into());
                }
                "--listen-control" => {
                    parsed.control_socket = Some(next_value(&mut arguments, &flag).into());
                }
                "--lease-ttl-ms" => {
                    parsed.lease_ttl_ms = Some(number(next_value(&mut arguments, &flag), &flag));
                }
                "--max-staged-bytes" => {
                    parsed.max_staged_bytes =
                        Some(number(next_value(&mut arguments, &flag), &flag));
                }
                "--max-staged-packs" => {
                    parsed.max_staged_packs =
                        Some(number(next_value(&mut arguments, &flag), &flag));
                }
                "--max-local-bytes" => {
                    parsed.max_local_bytes = Some(number(next_value(&mut arguments, &flag), &flag));
                }
                "--metadata-store-option" => {
                    parsed.metadata_path = Some(option_path(
                        next_value(&mut arguments, &flag),
                        "path",
                        &flag,
                    ));
                }
                "--object-store-option" => {
                    parsed.blob_root = Some(option_path(
                        next_value(&mut arguments, &flag),
                        "root",
                        &flag,
                    ));
                }
                "--durability" => {
                    parsed.durability = Some(utf8(next_value(&mut arguments, &flag), &flag));
                }
                other => panic!("unexpected legacy NodeRuntime argument {other:?}"),
            }
        }
        parsed
    }
}

fn next_value(arguments: &mut impl Iterator<Item = OsString>, flag: &str) -> OsString {
    arguments
        .next()
        .unwrap_or_else(|| panic!("{flag} requires one value"))
}

fn utf8(value: OsString, field: &str) -> String {
    value
        .into_string()
        .unwrap_or_else(|_| panic!("{field} is not UTF-8"))
}

fn number<T>(value: OsString, field: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = utf8(value, field);
    value
        .parse()
        .unwrap_or_else(|error| panic!("invalid {field} value {value:?}: {error}"))
}

fn option_path(value: OsString, key: &str, field: &str) -> PathBuf {
    let value = utf8(value, field);
    PathBuf::from(
        value
            .strip_prefix(&format!("{key}="))
            .unwrap_or_else(|| panic!("{field} requires {key}=...")),
    )
}

fn required<T>(value: Option<T>, field: &str) -> T {
    value.unwrap_or_else(|| panic!("missing {field}"))
}

fn serve_control(listener: UnixListener, engine: Arc<ChunkEngine>) {
    for connection in listener.incoming() {
        let Ok(connection) = connection else { return };
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || {
            let mut request = String::new();
            if BufReader::new(&connection).read_line(&mut request).is_err() {
                return;
            }
            let response = match request.trim().parse::<BlockdControlCommand>() {
                Ok(BlockdControlCommand::Drain) => match engine.drain_staged() {
                    Ok(generation) => BlockdControlResponse::ok(generation.to_string()),
                    Err(error) => BlockdControlResponse::error(error.to_string()),
                },
                Ok(BlockdControlCommand::Status) => {
                    match serde_json::to_string(&engine.durability_status()) {
                        Ok(status) => BlockdControlResponse::ok(status),
                        Err(error) => BlockdControlResponse::error(error.to_string()),
                    }
                }
                Err(error) => BlockdControlResponse::error(error.to_string()),
            };
            let _ = (&connection).write_all(response.to_wire().as_bytes());
        });
    }
}

fn main() {
    let args = LegacyRuntimeArgs::parse();
    assert_eq!(
        required(args.metadata_adapter, "metadata adapter"),
        "sqlite"
    );
    assert_eq!(required(args.object_adapter, "object adapter"), "file");

    let volume_id = required(args.volume_id, "volume ID");
    let attachment_id = required(args.attachment_id, "attachment ID");
    let data_dir = required(args.data_dir, "data directory");
    let metadata_path = required(args.metadata_path, "SQLite metadata path");
    let blob_root = required(args.blob_root, "FileBlobStore root");
    let nbd_socket = required(args.nbd_socket, "NBD socket");
    let control_socket = required(args.control_socket, "control socket");
    let lease_ttl_ms = required(args.lease_ttl_ms, "lease TTL");
    let size_bytes: u64 = number(
        std::env::var_os(TEST_VOLUME_SIZE_ENV)
            .unwrap_or_else(|| panic!("missing {TEST_VOLUME_SIZE_ENV}")),
        TEST_VOLUME_SIZE_ENV,
    );
    let attachment_epoch: i64 = number(
        std::env::var_os(TEST_ATTACHMENT_EPOCH_ENV)
            .unwrap_or_else(|| panic!("missing {TEST_ATTACHMENT_EPOCH_ENV}")),
        TEST_ATTACHMENT_EPOCH_ENV,
    );

    let metadata = SqliteMetadataStore::open(&metadata_path).expect("open SQLite test metadata");
    match metadata.create_volume(&volume_id, size_bytes) {
        Ok(()) | Err(MetaError::AlreadyExists(_)) => {}
        Err(error) => panic!("create SQLite test volume: {error}"),
    }
    let head = metadata
        .load_head(&volume_id)
        .expect("load SQLite test volume");
    assert_eq!(head.size_bytes, size_bytes, "test volume capacity drifted");
    drop(metadata);

    let durability = match args.durability.as_deref().unwrap_or("strict") {
        "strict" => (DurabilityMode::Strict, VolumeDurability::Strict),
        "relaxed" => (
            DurabilityMode::Relaxed {
                drain_interval_ms: 100,
            },
            VolumeDurability::Relaxed,
        ),
        other => panic!("unsupported test durability {other:?}"),
    };
    let (attachment, authority) = prepare_sqlite_authorized_serving(
        &metadata_path,
        &data_dir,
        SqliteTestVolumeGrant::new(
            &volume_id,
            &attachment_id,
            attachment_epoch,
            u64::try_from(lease_ttl_ms).expect("positive lease TTL"),
            durability.1,
        ),
    )
    .expect("prepare complete SQLite test authorization");
    let blob = Arc::new(FileBlobStore::open(blob_root).expect("open object fixture"));
    let mut config = EngineConfig::new(&volume_id, &data_dir, &attachment_id);
    config.lease_ttl_ms = lease_ttl_ms;
    config.durability = durability.0;
    config.max_staged_bytes = required(args.max_staged_bytes, "max staged bytes");
    config.max_staged_packs = required(args.max_staged_packs, "max staged packs");
    config.max_local_bytes = required(args.max_local_bytes, "max local bytes");
    let engine = ChunkEngine::attach_authorized_serving(config, attachment, blob, authority)
        .expect("adopt complete SQLite test authorization");

    let control = UnixListener::bind(control_socket).expect("bind test control socket");
    let nbd = UnixListener::bind(nbd_socket).expect("bind test NBD socket");
    let control_engine = Arc::clone(&engine);
    std::thread::spawn(move || serve_control(control, control_engine));
    cats_blockd::nbd::serve_unix(nbd, engine);
}
