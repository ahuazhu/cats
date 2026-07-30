use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn read_workspace_file(path: &str) -> String {
    let path = workspace_root().join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The units pass `--ch-cmdline` explicitly, so they override the binary
/// default rather than inheriting it.
#[test]
fn deployment_units_pin_kvm_clock_too() {
    for unit in [
        "deploy/metal/systemd/cats-noded.service",
        "deploy/aws/metal/cats-worker.service",
    ] {
        let text = read_workspace_file(unit);
        let line = text
            .lines()
            .find(|line| line.contains("--ch-cmdline"))
            .unwrap_or_else(|| panic!("{unit} no longer passes --ch-cmdline"));
        assert!(
            line.contains("clocksource=kvm-clock"),
            "{unit} overrides the guest cmdline without pinning kvm-clock: {line}"
        );
    }
}

#[test]
fn guest_image_installs_real_systemd_units_with_early_agent_readiness() {
    let builder = read_workspace_file("deploy/metal/build-guest-image.sh");
    for required in [
        "GUEST_INIT_MODE=${GUEST_INIT_MODE:-systemd}",
        "PRIMARY_INIT=/sbin/init",
        "FALLBACK_INIT=/usr/bin/cats-init",
        "\"$REPO/deploy/metal/guest-systemd/$unit\"",
        "serial-getty@ttyS0.service",
        "systemd-networkd-wait-online.service",
    ] {
        assert!(
            builder.contains(required),
            "guest image lost systemd build contract fragment {required:?}"
        );
    }
    assert!(
        !builder.contains("cat > \"$RF/etc/systemd/system/cats-"),
        "Guest systemd units must remain standalone source files"
    );

    let install_section = builder
        .split_once("# Keep the Guest unit definitions")
        .and_then(|(_, rest)| rest.split_once("# Grow the ext4 filesystem"))
        .map(|(section, _)| section)
        .expect("Guest unit install section");
    for unit in [
        "cats-grow-root.service",
        "cats-network.service",
        "cats-guest-agent.service",
    ] {
        assert!(
            install_section.contains(unit),
            "Guest image does not install {unit}"
        );
    }

    let unit_contracts = [
        (
            "cats-grow-root.service",
            &[
                "After=systemd-remount-fs.service",
                "Before=cats-guest-agent.service",
                "ExecStart=/sbin/resize2fs /dev/vda",
            ][..],
        ),
        (
            "cats-network.service",
            &[
                "After=systemd-remount-fs.service",
                "Before=cats-guest-agent.service network.target",
                "ExecStart=/usr/bin/cats-network-setup",
            ][..],
        ),
        (
            "cats-guest-agent.service",
            &[
                "Requires=cats-grow-root.service cats-network.service",
                "After=cats-grow-root.service cats-network.service systemd-remount-fs.service",
                "Before=sysinit.target",
                "WantedBy=sysinit.target",
            ][..],
        ),
    ];

    for (unit, required) in unit_contracts {
        let text = read_workspace_file(&format!("deploy/metal/guest-systemd/{unit}"));
        for fragment in required {
            assert!(
                text.contains(fragment),
                "{unit} lost systemd contract fragment {fragment:?}"
            );
        }
    }
}

#[test]
fn metal_acceptance_covers_systemd_service_lifecycle() {
    let text = read_workspace_file("deploy/metal/e2e.sh");
    for required in [
        "guest uses systemd as PID 1",
        "systemctl enable --now cats-e2e.service",
        "Warm preserves the service PID",
        "Warm does not restart the service",
        "Cold starts the service exactly once again",
    ] {
        assert!(
            text.contains(required),
            "metal acceptance lost systemd lifecycle oracle {required:?}"
        );
    }
}
