use std::path::Path;

#[test]
fn official_control_daemon_selects_only_production_router_compositions() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_path = manifest_dir.join("src/main.rs");
    let source = std::fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", source_path.display()));
    let server_path = manifest_dir.join("../../control-plane/src/server.rs");
    let server = std::fs::read_to_string(&server_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", server_path.display()));

    assert!(
        source.contains(
            "cats_control_plane::server::spawn_with_gateway_machine(server_config, gateway_machine)"
        ),
        "the official daemon must always compose the fixed Route v2 machine authority"
    );
    assert!(!source.contains("cats_control_plane::server::spawn(server_config)"));
    assert!(!source.contains("route_v2_machine_listen: Option"));
    assert!(!source.contains("route_v2_rotation_listen: Option"));
    assert!(!server.contains("pub async fn spawn(cfg: Config)"));
    assert!(!server.contains("Option<GatewayMachineConfig>"));
    assert!(source.contains("load_installed_gateway_machine_artifacts("));
    assert!(source.contains("load_installed_route_grant_v2_signer("));
    assert!(source.contains("load_installed_route_v2_rotation_operator_trust("));
    assert!(server.contains("GatewayMachineListener::spawn("));
    assert!(server.contains("RouteRotationMachineListener::spawn("));

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

#[test]
fn release_product_router_cli_console_and_docs_share_one_cutover_surface() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let router = std::fs::read_to_string(workspace.join("control-plane/src/api/mod.rs"))
        .expect("read production router");
    let cli =
        std::fs::read_to_string(workspace.join("cmd/cats/src/lib.rs")).expect("read shipped CLI");
    let user_script = std::fs::read_to_string(workspace.join("control-plane/ui/user.js"))
        .expect("read user console script");
    let user_markup = std::fs::read_to_string(workspace.join("control-plane/ui/user.html"))
        .expect("read user console markup");

    for route in [
        ".route(\"/v1/workspaces/{workspace}/cats\", cat_collection_route)",
        ".route(\"/v1/workspaces/{workspace}/disks\", disk_collection_route)",
        ".route(\"/v1/workspaces/{workspace}/cats/{cat}\", cat_item_route)",
        ".route(\"/v1/workspaces/{workspace}/disks/{disk}\", disk_item_route)",
        "\"/v1/workspaces/{workspace}/cats/{cat}/actions/run\"",
        "\"/v1/workspaces/{workspace}/cats/{cat}/actions/suspend\"",
        "\"/v1/workspaces/{workspace}/cats/{cat}/actions/warm\"",
        "\"/v1/workspaces/{workspace}/cats/{cat}/actions/cold\"",
        "\"/v1/workspaces/{workspace}/cats/{cat}/actions/destroy\"",
        "get(runtime_operations::get_runtime_operation)",
    ] {
        assert!(router.contains(route), "release router lost {route:?}");
    }
    assert!(
        cli.contains("Run { cat_id: String }")
            && cli.contains("Suspend { cat_id: String }")
            && cli.contains("Warm { cat_id: String }")
            && cli.contains("Cold { cat_id: String }")
            && cli.contains("Destroy { cat_id: String }")
            && cli.contains("PersistentDiskCreateV1Request")
            && cli.contains("CatCreateV2Request"),
        "shipped CLI lost the six-action product surface or the closed create DTOs"
    );

    for retired in [
        "data-cat-action",
        "data-disk-action",
        "/actions/",
        "#exec-form",
    ] {
        assert!(
            !user_script.contains(retired),
            "release user script retained mutation surface {retired:?}"
        );
    }
    assert!(
        user_script.contains("buildPersistentDiskCreateV1Request")
            && user_script.contains("sendDurablePersistentDiskCreateV1")
            && user_markup.contains("name=\"durability\" type=\"hidden\" value=\"strict\"")
            && !user_markup.contains("id=\"exec-dialog\""),
        "release console lost the closed PersistentDisk create or regained retired controls"
    );

    for locale in ["en", "zh-CN"] {
        let api = std::fs::read_to_string(workspace.join(format!(
            "control-plane/ui/public/docs/{locale}/api-reference.md"
        )))
        .expect("read API reference");
        let cli_reference = std::fs::read_to_string(workspace.join(format!(
            "control-plane/ui/public/docs/{locale}/cli-reference.md"
        )))
        .expect("read CLI reference");
        for current in [
            "POST /v1/workspaces/{workspace_id}/cats",
            "GET  /v1/workspaces/{workspace_id}/cats",
            "POST /v1/workspaces/{workspace_id}/disks",
            "GET  /v1/workspaces/{workspace_id}/disks",
            "GET /v1/workspaces/{workspace_id}/operations/{operation_id}",
            "/actions/run",
            "/actions/suspend",
            "/actions/warm",
            "/actions/cold",
            "/actions/destroy",
        ] {
            assert!(api.contains(current), "{locale} API docs lost {current:?}");
        }
        for retired in [
            "DELETE /v1/workspaces/{workspace_id}/cats",
            "DELETE /v1/workspaces/{workspace_id}/disks",
            "/actions/{verb}",
            "/snapshots",
        ] {
            assert!(
                !api.contains(retired),
                "{locale} API docs advertise retired route {retired:?}"
            );
        }
        for current in [
            "cats create NAME --boot-image-digest",
            "cats run CAT_ID",
            "cats suspend CAT_ID",
            "cats warm CAT_ID",
            "cats cold CAT_ID",
            "cats destroy CAT_ID",
            "cats disk create NAME --size SIZE",
            "cats operation get OPERATION_ID",
        ] {
            assert!(
                cli_reference.contains(current),
                "{locale} CLI docs lost {current:?}"
            );
        }
        for retired in [
            "cats disk delete",
            "cats disk snapshot",
            "cats mount",
            "cats unmount",
            "cats expose",
            "cats start",
            "cats stop",
            "cats delete",
            "cats resume",
        ] {
            assert!(
                !cli_reference.contains(retired),
                "{locale} CLI docs advertise retired command {retired:?}"
            );
        }
    }
}
