//! Release-binary composition tests. Data-plane image, GC, fencing and cold
//! restore invariants remain exercised in `cats-blockd` engine tests; this
//! suite proves the shipped CLI cannot recompose their retired authority.

use std::process::Command;

#[test]
fn legacy_authority_flags_are_rejected_by_clap_before_any_io() {
    let directory = tempfile::tempdir().unwrap();
    for legacy in [
        vec!["--attachment-epoch", "7"],
        vec!["--create-volume-size", "4194304"],
        vec!["--collect-garbage"],
        vec!["--seed-image-id", "legacy-image"],
        vec!["--seed-image", "/legacy/image.raw"],
        vec!["--listen-tcp", "127.0.0.1:10809"],
    ] {
        let data_dir = directory.path().join(legacy[0].trim_start_matches('-'));
        let output = Command::new(env!("CARGO_BIN_EXE_cats-blockd"))
            .args(&legacy)
            .arg("--object-store-adapter")
            .arg("definitely-not-an-adapter")
            .arg("--data-dir")
            .arg(&data_dir)
            .output()
            .expect("run cats-blockd");
        assert!(!output.status.success(), "legacy flag parsed: {legacy:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected argument"),
            "legacy flag reached process composition: {legacy:?}: {stderr}"
        );
        assert!(!data_dir.exists(), "legacy flag performed local I/O");
    }
}

#[test]
fn serving_without_a_complete_artifact_fails_before_adapter_open() {
    let directory = tempfile::tempdir().unwrap();
    let data_dir = directory.path().join("data");
    let output = Command::new(env!("CARGO_BIN_EXE_cats-blockd"))
        .args([
            "--volume-id",
            "vol_ungranted",
            "--attachment-id",
            "att_ungranted",
            "--metadata-store-adapter",
            "postgres",
            "--object-store-adapter",
            "definitely-not-an-adapter",
        ])
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--listen-unix")
        .arg(directory.path().join("nbd.sock"))
        .output()
        .expect("run cats-blockd");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("complete authorized serving artifact"),
        "unexpected rejection: {stderr}"
    );
    assert!(!stderr.contains("unknown object-store adapter"));
    assert!(!data_dir.exists(), "ungranted serving performed local I/O");
}

#[test]
fn release_help_exposes_only_artifact_authorized_volume_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_cats-blockd"))
        .arg("--help")
        .output()
        .expect("run cats-blockd --help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    let protocol = include_str!("../../../docs/specs/blockd-protocol.md");
    assert!(help.contains("--authorized-serving-spec"));
    assert!(help.contains("--authorized-control-spec"));
    for legacy in [
        "--attachment-epoch",
        "--create-volume-size",
        "--collect-garbage",
        "--seed-image-id",
        "--seed-image",
        "--listen-tcp",
    ] {
        assert!(!help.contains(legacy), "release help exposes {legacy}");
    }
    for retired_gc_flag in [
        "--attachment-epoch",
        "--collect-garbage",
        "--gc-interval-ms",
    ] {
        assert!(
            !protocol.contains(retired_gc_flag),
            "frozen protocol advertises removed release flag {retired_gc_flag}"
        );
    }
    assert!(protocol.contains("blockd不执行volume delete"));
    assert!(protocol.contains("product DiskSnapshot/GC仍是明确开放项"));
}

#[test]
fn publishing_an_image_remains_a_volume_free_object_store_operation() {
    use std::io::Write as _;

    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("image.raw");
    let mut file = std::fs::File::create(&image).unwrap();
    file.write_all(b"immutable golden image").unwrap();
    file.sync_all().unwrap();
    let object_root = directory.path().join("objects");

    let publish = || {
        Command::new(env!("CARGO_BIN_EXE_cats-blockd"))
            .arg("--publish-image")
            .arg(&image)
            .arg("--object-store-adapter")
            .arg("file")
            .arg("--object-store-option")
            .arg(format!("root={}", object_root.display()))
            .output()
            .expect("run cats-blockd --publish-image")
    };
    let first = publish();
    assert!(
        first.status.success(),
        "publish failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = publish();
    assert!(second.status.success());
    assert_eq!(
        first.stdout, second.stdout,
        "image publication is idempotent"
    );
    assert!(String::from_utf8_lossy(&first.stdout).starts_with("IMAGE "));
}
