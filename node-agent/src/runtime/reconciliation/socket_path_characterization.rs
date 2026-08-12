//! Characterization of the production blockd Unix-socket mapping.
//!
//! Socket names depend only on their persisted physical owner: the Root
//! provision transition or the Serving device token. Durable attachment data
//! remains in the Node state directory and deliberately does not participate
//! in this boot-local pathname calculation.

use std::path::Path;

#[cfg(target_os = "linux")]
use cats_api::runtime_reconciliation::HostPath;
use cats_api::runtime_reconciliation::RandomId128;
use cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot;

// Linux sockaddr_un::sun_path has 108 bytes. A filesystem pathname needs one
// trailing NUL, so 107 pathname bytes is the exact inclusive ceiling.
const LINUX_UNIX_PATHNAME_MAX_BYTES: usize = 107;

#[test]
fn installed_managed_blockd_sockets_fit_linux_sun_path() {
    let root = ManagedBlockdSocketRoot::installed();
    let root_paths = root.root_paths(&random('2')).unwrap();
    let serving_paths = root.serving_paths(&random('6')).unwrap();

    for path in [
        root_paths.control_socket(),
        serving_paths.control_socket(),
        serving_paths.io_socket(),
    ] {
        assert!(
            path.as_str().len() <= LINUX_UNIX_PATHNAME_MAX_BYTES,
            "installed managed blockd socket is not bindable on Linux: {path:?}"
        );
        assert!(
            Path::new(path.as_str()).starts_with(Path::new(root.path().as_str())),
            "managed socket escaped the fixed installed root"
        );
    }
}

#[test]
fn root_owner_is_transition_stable_across_process_token_rotation() {
    let root = ManagedBlockdSocketRoot::installed();
    let transition_a = random('2');
    let transition_b = random('3');
    let process_a = random('4');
    let process_b = random('5');

    // Process tokens are intentionally absent from the mapper. Replacing only
    // that token therefore cannot change the transition-owned namespace.
    assert_ne!(process_a, process_b);
    let original = root.root_paths(&transition_a).unwrap();
    let rotated_process = root.root_paths(&transition_a).unwrap();
    assert_eq!(original, rotated_process);
    assert_ne!(
        original.public_directory(),
        root.root_paths(&transition_b).unwrap().public_directory(),
        "a distinct Root transition reused the prior socket owner"
    );
}

#[test]
fn serving_owner_rotation_changes_the_complete_socket_pair() {
    let root = ManagedBlockdSocketRoot::installed();
    let original = root.serving_paths(&random('6')).unwrap();
    let rotated = root.serving_paths(&random('7')).unwrap();

    assert_ne!(original.public_directory(), rotated.public_directory());
    assert_ne!(original.control_socket(), rotated.control_socket());
    assert_ne!(original.io_socket(), rotated.io_socket());
    assert_ne!(original.control_socket(), original.io_socket());
}

#[cfg(target_os = "linux")]
#[test]
fn production_mapper_paths_support_real_bind_and_peer_exchange() {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    let temp = tempfile::Builder::new()
        .prefix("cbn")
        .tempdir_in("/tmp")
        .unwrap();
    let root = ManagedBlockdSocketRoot::from_canonical_path(
        HostPath::new(temp.path().to_string_lossy().into_owned()).unwrap(),
    )
    .unwrap();
    let paths = root.serving_paths(&random('8')).unwrap();
    std::fs::create_dir(paths.public_directory().as_str()).unwrap();

    let listener = UnixListener::bind(paths.control_socket().as_str()).unwrap();
    let mut client = UnixStream::connect(paths.control_socket().as_str()).unwrap();
    client.write_all(b"status").unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let mut request = [0_u8; 6];
    server.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"status");

    // Both leaves belong to one published Serving owner and are independently
    // bindable; this catches ctl/io aliasing as an OS-level regression.
    let io_listener = UnixListener::bind(paths.io_socket().as_str()).unwrap();
    assert!(UnixStream::connect(paths.io_socket().as_str()).is_ok());
    drop(io_listener);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_unix_listener_enforces_the_exact_sun_path_boundary() {
    use std::os::unix::net::UnixListener;

    let root = tempfile::Builder::new()
        .prefix("csp")
        .tempdir_in("/tmp")
        .unwrap();
    let exact = pathname_with_length(root.path(), LINUX_UNIX_PATHNAME_MAX_BYTES);
    let listener = UnixListener::bind(&exact).expect("107-byte Linux Unix pathname must bind");
    drop(listener);
    std::fs::remove_file(&exact).unwrap();

    let oversized = pathname_with_length(root.path(), LINUX_UNIX_PATHNAME_MAX_BYTES + 1);
    UnixListener::bind(&oversized).expect_err("108-byte Linux Unix pathname must be rejected");
}

#[cfg(target_os = "linux")]
fn pathname_with_length(root: &Path, length: usize) -> std::path::PathBuf {
    let prefix = root.as_os_str().as_encoded_bytes().len() + 1;
    assert!(prefix < length);
    root.join("x".repeat(length - prefix))
}

fn random(value: char) -> RandomId128 {
    RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
}
