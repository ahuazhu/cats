use std::path::Path;

#[test]
fn blockd_has_no_self_acquire_composition() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let daemon = std::fs::read_to_string(workspace.join("cmd/blockd/src/main.rs"))
        .expect("read blockd daemon");
    let engine =
        std::fs::read_to_string(workspace.join("blockd/src/engine/mod.rs")).expect("read engine");

    assert!(
        daemon.contains("ChunkEngine::attach_granted_epoch")
            && !daemon.contains("ChunkEngine::attach("),
        "blockd still starts through its lease-acquiring compatibility path"
    );
    assert!(
        !engine.contains("AttachmentMode::Acquire") && !engine.contains("metadata.acquire_lease"),
        "blockd still owns a lease-acquire transition"
    );
}
