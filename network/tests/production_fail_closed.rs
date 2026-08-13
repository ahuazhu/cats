use std::process::Command;

const FORBIDDEN_SHIPPED_GATEWAY_SURFACES: [&str; 7] = [
    "CATS_SHARED_ROUTE_CACHE_TABLE",
    "/v1/routes/resolve",
    "/v1/routes/wake",
    "/v1/cats/",
    "/etc/cats/route-v2/signer-private-key.pem",
    "/etc/cats/route-v2/public-key-ring.v1.json",
    "CATS_ROUTE_GRANT_PRIVATE_KEY_FILE",
];

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn embedded_forbidden_surface(binary: &[u8]) -> Option<&'static str> {
    FORBIDDEN_SHIPPED_GATEWAY_SURFACES
        .into_iter()
        .find(|forbidden| contains_bytes(binary, forbidden.as_bytes()))
}

#[test]
fn legacy_surface_probe_ignores_dependency_paths_but_detects_cats_routes() {
    assert_eq!(
        embedded_forbidden_surface(b"src/client/legacy/connect/proxy/tunnel.rs"),
        None
    );
    for legacy_surface in [
        b"CATS_SHARED_ROUTE_CACHE_TABLE".as_slice(),
        b"/v1/routes/resolve".as_slice(),
        b"/v1/routes/wake".as_slice(),
        b"/v1/cats/cat_a/proxy".as_slice(),
        b"/v1/cats/cat_a/proxy-websocket".as_slice(),
        b"/etc/cats/route-v2/signer-private-key.pem".as_slice(),
        b"/etc/cats/route-v2/public-key-ring.v1.json".as_slice(),
        b"CATS_ROUTE_GRANT_PRIVATE_KEY_FILE".as_slice(),
    ] {
        assert!(
            embedded_forbidden_surface(legacy_surface).is_some(),
            "known legacy Cats surface escaped the shipped-binary probe"
        );
    }
}

#[test]
fn shipped_gateway_binary_contains_only_terminal_route_v2_composition() {
    let output = Command::new(env!("CARGO_BIN_EXE_cats-gatewayd"))
        .args([
            "--listen",
            "127.0.0.1:0",
            "--control-plane-url",
            "http://control.internal:7443",
        ])
        .env("CATS_SHARED_ROUTE_CACHE_TABLE", "must-not-be-read")
        .output()
        .expect("run cats-gatewayd");

    assert!(
        !output.status.success(),
        "missing fixed artifacts must fail startup"
    );
    assert!(
        output.stdout.is_empty(),
        "fail-closed binary printed READY output"
    );
    assert!(
        String::from_utf8(output.stderr)
            .expect("stderr is UTF-8")
            .contains("must be a canonical HTTPS authority"),
        "startup did not reject plaintext Control transport before bind"
    );

    let binary = std::fs::read(env!("CARGO_BIN_EXE_cats-gatewayd"))
        .expect("read the exact tested gateway binary");
    assert!(
        embedded_forbidden_surface(&binary).is_none(),
        "shipped gateway binary still embeds legacy surface {:?}",
        embedded_forbidden_surface(&binary)
    );
    for required in [
        // The sole local operational route is an exact GET handled only after
        // bounded public head parsing. Every application route uses v2.
        "/healthz",
        "/v1/internal/routes/resolve",
        "/v1/internal/routes/tunnel",
        "/etc/cats/route-v2/node-server-ca-bundle.pem",
        "/etc/cats/route-v2/gateway-machine-client-certificate.pem",
        "/etc/cats/route-v2/gateway-machine-client-private-key.pem",
    ] {
        assert!(
            contains_bytes(&binary, required.as_bytes()),
            "shipped Gateway omitted terminal Route v2 surface {required}"
        );
    }
}
