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
