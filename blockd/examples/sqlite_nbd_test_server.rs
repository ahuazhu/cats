//! Explicit test program for kernel-NBD integration evidence which needs a
//! killable process. This is deliberately not the `cats-blockd` production
//! binary and has no Cargo feature that can re-enable legacy authority there.

use std::path::PathBuf;
use std::sync::Arc;

use cats_blockd::engine::{ChunkEngine, EngineConfig};
use cats_object_store_file::FileBlobStore;
use cats_storage::authority::VolumeDurability;
use cats_test_support::{prepare_sqlite_authorized_serving, SqliteTestVolumeGrant};

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let volume_id = arguments.next().expect("volume ID");
    let attachment_id = arguments.next().expect("attachment ID");
    let epoch: i64 = arguments
        .next()
        .expect("attachment epoch")
        .to_string_lossy()
        .parse()
        .expect("numeric attachment epoch");
    let lease_ttl_ms: i64 = arguments
        .next()
        .expect("lease TTL")
        .to_string_lossy()
        .parse()
        .expect("numeric lease TTL");
    let data_dir = PathBuf::from(arguments.next().expect("data directory"));
    let metadata_path = PathBuf::from(arguments.next().expect("metadata path"));
    let blob_root = PathBuf::from(arguments.next().expect("blob root"));
    let socket = PathBuf::from(arguments.next().expect("NBD socket"));
    assert!(
        arguments.next().is_none(),
        "unexpected test server argument"
    );
    let volume_id = volume_id.to_str().expect("UTF-8 volume ID");
    let attachment_id = attachment_id.to_str().expect("UTF-8 attachment ID");

    let blob = Arc::new(FileBlobStore::open(blob_root).expect("open object fixture"));
    let mut config = EngineConfig::new(volume_id, &data_dir, attachment_id);
    config.lease_ttl_ms = lease_ttl_ms;
    let (attachment, authority) = prepare_sqlite_authorized_serving(
        &metadata_path,
        &data_dir,
        SqliteTestVolumeGrant::new(
            volume_id,
            attachment_id,
            epoch,
            u64::try_from(lease_ttl_ms).expect("positive lease TTL"),
            VolumeDurability::Strict,
        ),
    )
    .expect("prepare complete external test authorization");
    let engine = ChunkEngine::attach_authorized_serving(config, attachment, blob, authority)
        .expect("adopt complete external test authorization");
    let listener = std::os::unix::net::UnixListener::bind(socket).expect("bind test NBD socket");
    cats_blockd::nbd::serve_unix(listener, engine);
}
