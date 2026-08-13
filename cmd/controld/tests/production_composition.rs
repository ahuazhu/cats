use std::path::Path;

#[test]
fn official_control_daemon_selects_only_production_router_compositions() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = std::fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", source_path.display()));

    for production_composition in [
        "cats_control_plane::server::spawn(server_config)",
        "cats_control_plane::server::spawn_with_gateway_machine(server_config, machine)",
    ] {
        assert!(
            source.contains(production_composition),
            "the official control daemon lost production composition {production_composition:?}"
        );
    }

    for retired_test_composition in [
        "spawn_for_retired_product_tests",
        "retired_product_support_router",
    ] {
        assert!(
            !source.contains(retired_test_composition),
            "the official control daemon references retired test composition {retired_test_composition:?}"
        );
    }
}

#[test]
fn official_control_daemon_has_no_legacy_volume_authority() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_path = manifest_dir.join("src/main.rs");
    let source = std::fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", source_path.display()));
    let manifest_path = manifest_dir.join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display()));
    let workspace = manifest_dir.join("../..");
    let kubernetes = std::fs::read_to_string(
        workspace.join("deploy/aws/terraform/modules/cats-kubernetes/main.tf"),
    )
    .expect("read control-plane deployment");
    let metal_unit =
        std::fs::read_to_string(workspace.join("deploy/metal/systemd/cats-controld.service"))
            .expect("read metal control-plane unit");

    for retired in [
        "open_metadata_store",
        "metadata_store_adapter",
        "metadata_store_options",
        "PostgresMetadataStoreFactory",
        "SqliteMetadataStoreFactory",
    ] {
        assert!(
            !source.contains(retired),
            "the official control daemon still composes legacy volume authority {retired:?}"
        );
    }
    for retired_dependency in ["cats-metadata-store-sqlite", "cats-metadata-store-postgres"] {
        assert!(
            !manifest.contains(retired_dependency),
            "the official control daemon still links {retired_dependency}"
        );
    }
    for deployment in [kubernetes.as_str(), metal_unit.as_str()] {
        assert!(
            !deployment.contains("--metadata-store-adapter")
                && !deployment.contains("CATS_METADATA_STORE_ARGS"),
            "the control-plane deployment still supplies legacy metadata authority arguments"
        );
    }
}
