use std::io::ErrorKind;
use std::net::TcpListener;
use std::process::Command;

const CUTOVER_BLOCKER: &str = "cats-gatewayd is intentionally unavailable: Route Grant v2 is not composed: missing Gateway workload credential and policy authority and Route v2 signer and Node key-ring distribution and Control machine-authenticated resolve transport and public ingress proxy/listener composition; production ingress remains fail-closed";
const FORBIDDEN_SHIPPED_GATEWAY_SURFACES: [&str; 4] = [
    "CATS_SHARED_ROUTE_CACHE_TABLE",
    "/v1/routes/resolve",
    "/v1/routes/wake",
    "/v1/cats/",
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
    ] {
        assert!(
            embedded_forbidden_surface(legacy_surface).is_some(),
            "known legacy Cats surface escaped the shipped-binary probe"
        );
    }
}

#[test]
fn shipped_gateway_binary_exits_before_listening_or_legacy_outbound() {
    let canary = TcpListener::bind("127.0.0.1:0").expect("bind outbound canary");
    canary
        .set_nonblocking(true)
        .expect("make outbound canary nonblocking");
    let canary_url = format!("http://{}", canary.local_addr().expect("canary address"));

    let output = Command::new(env!("CARGO_BIN_EXE_cats-gatewayd"))
        .args([
            "--listen",
            "127.0.0.1:0",
            "--control-plane-url",
            &canary_url,
        ])
        .env("CATS_SHARED_ROUTE_CACHE_TABLE", "must-not-be-read")
        .output()
        .expect("run cats-gatewayd");

    assert!(
        !output.status.success(),
        "cutover blocker unexpectedly exited 0"
    );
    assert!(
        output.stdout.is_empty(),
        "fail-closed binary printed READY output"
    );
    assert_eq!(
        String::from_utf8(output.stderr)
            .expect("stderr is UTF-8")
            .trim(),
        CUTOVER_BLOCKER
    );
    assert!(
        matches!(canary.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
        "fail-closed binary contacted the legacy control-plane canary"
    );

    let binary = std::fs::read(env!("CARGO_BIN_EXE_cats-gatewayd"))
        .expect("read the exact tested gateway binary");
    assert!(
        embedded_forbidden_surface(&binary).is_none(),
        "shipped gateway binary still embeds legacy surface {:?}",
        embedded_forbidden_surface(&binary)
    );
}
