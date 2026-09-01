#![cfg(all(feature = "protocol-compat", feature = "artifacts-compat"))]

fn assert_type<T>() {}

#[test]
fn former_protocol_and_artifact_module_paths_remain_available() {
    assert_type::<cats_api::blockd::DurabilityStatus>();
    assert_type::<cats_api::error::ErrorBody>();
    assert_type::<cats_api::guest::GuestRequest>();
    assert_type::<cats_api::metering::CatUsageCheckpoint>();
    assert_type::<cats_api::node_identity::Ed25519RequestSigner>();
    assert_type::<cats_api::oci::DeployOciRequest>();
    assert_type::<cats_api::production_mutation_admission::ProductionCutoverOperatorTrustBundle>();
    assert_type::<cats_api::runtime_reconciliation::Id>();
    assert_type::<cats_api::semantic_control::CatView>();
    assert_type::<cats_api::sessions::ExecRequest>();
    assert_type::<cats_api::runtime_artifacts::InstalledGuestRuntimeProfileReceipt>();

    assert_eq!(cats_api::chunk::LOGICAL_BLOCK_SIZE, 512);
    assert_eq!(
        cats_api::runtime_node_authority::RUNTIME_NODE_AUTHORITY_PATH,
        "/v1/admin/runtime/node-authority-applies"
    );
}
