use std::path::Path;

#[test]
fn blockd_has_no_self_acquire_composition() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let daemon = std::fs::read_to_string(workspace.join("cmd/blockd/src/main.rs"))
        .expect("read blockd daemon");
    let engine =
        std::fs::read_to_string(workspace.join("blockd/src/engine/mod.rs")).expect("read engine");

    let manifest = std::fs::read_to_string(workspace.join("cmd/blockd/Cargo.toml"))
        .expect("read blockd daemon manifest");

    assert!(daemon.contains("ChunkEngine::attach_authorized_serving"));
    assert!(daemon.contains("ChunkEngine::attach_authorized_control_only"));
    for retired in [
        "ChunkEngine::attach_granted_epoch",
        "open_metadata_store",
        "SqliteMetadataStoreFactory",
        "PostgresMetadataStoreFactory",
        "attachment_epoch: Option<i64>",
        "create_volume_size:",
        "collect_garbage:",
        "listen_tcp:",
        "seed_image_id:",
    ] {
        assert!(
            !daemon.contains(retired),
            "release daemon retains {retired}"
        );
    }
    let dependencies = manifest
        .split_once("[dev-dependencies]")
        .map(|(dependencies, _)| dependencies)
        .unwrap_or(&manifest);
    assert!(
        !dependencies.contains("cats-metadata-store-sqlite"),
        "release daemon retains the SQLite legacy authority adapter"
    );
    assert!(
        !engine.contains("AttachmentMode::Acquire") && !engine.contains("metadata.acquire_lease"),
        "blockd still owns a lease-acquire transition"
    );
    for raw_constructor in ["attach_granted_epoch", "attach_control_only"] {
        let location = engine
            .find(raw_constructor)
            .expect("raw test constructor exists");
        let prefix = &engine[location.saturating_sub(80)..location];
        assert!(
            prefix.contains("#[cfg(test)]"),
            "raw owner/epoch constructor is available in release: {raw_constructor}"
        );
    }
}
