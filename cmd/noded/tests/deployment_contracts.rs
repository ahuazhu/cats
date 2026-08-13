use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

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

#[test]
fn production_deployment_selects_each_control_plane_image_target() {
    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    let control_plane_step = workflow
        .split_once("      - name: Build and push control-plane image")
        .and_then(|(_, rest)| rest.split_once("\n      - name:"))
        .map(|(step, _)| step)
        .expect("control-plane image build step");
    assert!(
        control_plane_step
            .lines()
            .any(|line| line.trim() == "target: runtime"),
        "the control-plane build must select the runtime target explicitly; otherwise Docker builds the final credential-refresher stage"
    );

    let refresher_step = workflow
        .split_once("      - name: Build and push credential-refresher image")
        .and_then(|(_, rest)| rest.split_once("\n      - name:"))
        .map(|(step, _)| step)
        .expect("credential-refresher image build step");
    assert!(
        refresher_step
            .lines()
            .any(|line| line.trim() == "target: credential-refresher"),
        "the credential-refresher build must select its dedicated target"
    );
}

#[test]
fn deployment_units_take_the_pinned_guest_cmdline_only_from_the_shared_receipt() {
    let builder = read_workspace_file("deploy/metal/build-guest-image.sh");
    assert!(builder.contains(
        r#"\"kernel_cmdline\":\"console=ttyS0 root=/dev/vda rw clocksource=kvm-clock\""#
    ));
    for unit in [
        "deploy/metal/systemd/cats-noded.service",
        "deploy/aws/metal/cats-worker.service",
    ] {
        let text = read_workspace_file(unit);
        assert!(text.contains(
            "--guest-runtime-profile-receipt-file /opt/cats/release/guest-runtime-profile.v1.json"
        ));
        assert!(text.contains("--vmm-launcher-bin /opt/cats/bin/cats-vmm-launcher"));
        let recovery = text
            .find("ExecStartPre=/opt/cats/bin/install-guest-runtime-release startup-recover")
            .expect("service restart recovery gate");
        let start = text
            .find("ExecStart=/opt/cats/bin/cats-noded")
            .expect("Node start");
        assert!(
            recovery < start,
            "{unit} must recover or block before Node exec"
        );
        assert!(!text.contains("--ch-cmdline"));
    }
}

#[test]
fn node_agent_killmode_is_explicit_without_owning_per_cat_services() {
    for unit in [
        "deploy/metal/systemd/cats-noded.service",
        "deploy/aws/metal/cats-worker.service",
    ] {
        let text = read_workspace_file(unit);
        let kill_modes = text
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("KillMode="))
            .collect::<Vec<_>>();
        assert_eq!(
            kill_modes,
            ["KillMode=control-group"],
            "{unit} must explicitly reap every process in the Agent service cgroup"
        );
        assert!(
            text.contains("cats=0/orphans=0"),
            "{unit} must require a drained, empty node before a controlled stop or restart"
        );
    }

    let metal_readme = read_workspace_file("deploy/metal/README.md");
    let first_install = metal_readme
        .find("仅限首次安装、尚未创建任何 Cat")
        .expect("metal install restart is explicitly limited to a fresh empty node");
    let restart = metal_readme
        .find("systemctl restart cats-noded")
        .expect("metal installation documents its required configuration restart");
    let later_cordon_guard = metal_readme
        .find("first apply a reviewed A23 cordon")
        .expect("metal restart instructions require a reviewed A23 cordon");
    let later_empty_guard = metal_readme
        .find("no assigned Desired runtimes or physical residue")
        .expect("metal restart instructions require an empty, residue-free node");
    assert!(
        first_install < restart
            && restart < later_cordon_guard
            && later_cordon_guard < later_empty_guard,
        "metal restart instructions must limit the direct command to first install and then document the drain/idle guard"
    );

    let process_owner =
        read_workspace_file("node-agent/src/runtime/reconciliation/systemd_root_provision.rs");
    for exact in [
        "const SYSTEM_SLICE: &str = \"system.slice\";",
        "const ROOT_PROVISION_KILL_MODE: &str = \"control-group\";",
        ".arg(format!(\"--slice={SYSTEM_SLICE}\"))",
        ".arg(format!(\"--property=KillMode={ROOT_PROVISION_KILL_MODE}\"))",
        ".arg(format!(\"--property=Restart={ROOT_PROVISION_RESTART}\"))",
    ] {
        assert!(
            process_owner.contains(exact),
            "per-Cat process ownership lost its independent systemd-service contract {exact:?}"
        );
    }

    let linux_gate = read_workspace_file("scripts/linux-gate.sh");
    for exact in [
        "agent_unit=cats-noded.service",
        "cat_unit=cats-serving-11111111111111111111111111111111.service",
        "systemctl stop \"$agent_unit\"",
        "systemctl restart \"$agent_unit\"",
        "cat_start_ticks_after_restart",
        "cat_control_group_after_restart",
        "systemctl stop \"$cat_unit\"",
    ] {
        assert!(
            linux_gate.contains(exact),
            "the real PID1 Linux gate lacks the production Agent-stop/restart sibling-adoption probe {exact:?}"
        );
    }
}

#[test]
fn production_aws_worker_does_not_write_legacy_schedulability_state() {
    let unit = read_workspace_file("deploy/aws/metal/cats-worker.service");
    assert!(
        !unit.contains("--initially-cordoned") && !unit.contains("--node-id"),
        "Agent registration must not manufacture or double-write legacy Node schedulability state"
    );
    assert!(unit.contains("/etc/cats/identity/node-identity.v1.json"));
}

#[test]
fn production_aws_worker_can_cut_over_to_proxy_without_client_set_pinning() {
    let unit = read_workspace_file("deploy/aws/metal/cats-worker.service");
    for expected in [
        "Environment=CATS_POSTGRES_SESSION_SETUP=client",
        "--metadata-store-option session-setup=${CATS_POSTGRES_SESSION_SETUP}",
    ] {
        assert!(
            unit.contains(expected),
            "production worker is missing PostgreSQL proxy contract {expected:?}"
        );
    }
    assert!(
        unit.find("Environment=CATS_POSTGRES_SESSION_SETUP=client")
            < unit.find("EnvironmentFile=/etc/cats/worker.env"),
        "worker.env must be able to override the backward-compatible client default"
    );
    assert!(
        !unit.contains("session-setup=$CATS_POSTGRES_SESSION_SETUP"),
        "systemd does not expand an unbraced variable embedded in an argument; the worker would receive the literal variable name and restart forever"
    );
}

#[test]
fn production_platform_example_keeps_two_workers_in_distinct_subnets() {
    let variables =
        read_workspace_file("deploy/aws/terraform/stacks/platform/platform.tfvars.example");
    let variables = variables.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        variables.contains("metal_workers = {"),
        "the production example must retain worker capacity after one bare-metal host is lost"
    );
    assert!(
        variables.contains("\"metal-2\" = { subnet_index = 0")
            && variables.contains("\"metal-1\" = { subnet_index = 1"),
        "the imported workers must retain their exact stable subnet identities"
    );

    let platform = read_workspace_file("deploy/aws/terraform/stacks/platform/main.tf")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        platform.contains("subnet_id = module.network.private_subnet_ids[each.value.subnet_index]"),
        "bare-metal workers must be distributed across the configured private subnets"
    );

    let deployment = read_workspace_file(
        "deploy/aws/terraform/stacks/production-infrastructure/production.tfvars.example",
    );
    for node_id in ["\"metal-2\" =", "\"metal-1\" ="] {
        assert!(
            deployment.contains(node_id),
            "the worker deployment example must manage both stable node identities: {node_id}"
        );
    }
}

#[test]
fn manual_worker_bootstrap_refuses_the_example_identity() {
    let example = read_workspace_file("deploy/aws/metal/worker.env.example");
    assert!(
        !example.contains("CATS_NODE_ID=") && !example.contains("CATS_NODE_ADVERTISE_URL="),
        "the worker environment must not be a second Node identity authority"
    );
    assert!(
        !example.contains("CATS_AUTH_TOKEN="),
        "signed workers must not receive the retired shared Control bearer"
    );

    let installer = read_workspace_file("deploy/aws/metal/install-worker.sh");
    assert!(installer.contains("validate-node-identity-installation.sh"));
    let validator = read_workspace_file("deploy/aws/metal/validate-node-identity-installation.sh");
    for expected in [
        "identity_dir=/etc/cats/identity",
        "node-identity.v1.json",
        "node-registration-key.pem",
        "node-registration-credential-id",
        "0:0:700",
        "0:0:600:1",
    ] {
        assert!(
            validator.contains(expected),
            "the validator must enforce provisioner-owned identity before startup: {expected:?}"
        );
    }
    assert!(
        installer.find("validate-node-identity-installation.sh")
            < installer.find("apt-get update -q"),
        "identity presence validation must happen before the expensive bootstrap starts"
    );
}

#[test]
fn production_worker_release_rejects_and_removes_the_shared_control_bearer() {
    let variables =
        read_workspace_file("deploy/aws/terraform/modules/metal-worker-deployment/variables.tf");
    assert!(!variables.contains("var.worker_runtime_secret_data[\"CATS_AUTH_TOKEN\"]"));
    assert!(variables.contains("signed workers must not receive CATS_AUTH_TOKEN"));

    let deployment =
        read_workspace_file("deploy/aws/terraform/modules/metal-worker-deployment/main.tf");
    assert!(deployment.contains("if (keys - [\"CATS_POSTGRES_URL\"]) != []"));
    assert!(deployment.contains("[to_entries[] | \"\\(.key)=\\(.value)\"] | join(\"\\n\")"));
    assert!(deployment.contains("if (key == \"CATS_AUTH_TOKEN\")"));

    let installer = read_workspace_file("deploy/aws/metal/install-worker.sh");
    assert!(installer.contains("$1 != \"CATS_AUTH_TOKEN\""));
    assert!(installer.contains("after-remove-worker-shared-bearer"));

    let stack =
        read_workspace_file("deploy/aws/terraform/stacks/production-infrastructure/main.tf");
    assert!(!stack.contains("length(var.worker_runtime_secret_data) > 0"));
}

#[test]
fn guest_builder_installs_musl_target_for_the_pinned_toolchain() {
    let builder = read_workspace_file("deploy/metal/build-guest-image.sh");
    let static_agent_build = builder
        .split_once("# 0. Static guest agent (musl)")
        .and_then(|(_, rest)| rest.split_once("# 1. Kernel"))
        .map(|(section, _)| section)
        .expect("static Guest Agent build section");

    let enter_repository = static_agent_build
        .find("cd \"$REPO\"")
        .expect("Guest build must enter the repository");
    let install_target = static_agent_build
        .find("rustup target add x86_64-unknown-linux-musl")
        .expect("Guest build must install the musl Rust target");
    let build_agent = static_agent_build
        .find("cargo build --release -p cats-guest-agent --target x86_64-unknown-linux-musl")
        .expect("Guest build must compile a static Guest Agent");

    assert!(
        enter_repository < install_target && install_target < build_agent,
        "rustup must resolve the musl target after entering the repository so it installs into rust-toolchain.toml's pinned toolchain"
    );
}

#[test]
fn guest_image_installs_real_systemd_units_with_early_agent_readiness() {
    let builder = read_workspace_file("deploy/metal/build-guest-image.sh");
    for required in [
        "GUEST_INIT_MODE=${GUEST_INIT_MODE:-systemd}",
        "umask 022",
        "PRIMARY_INIT=/sbin/init",
        "FALLBACK_INIT=/usr/bin/cats-init",
        "mount --make-rprivate /",
        "\"$REPO/deploy/metal/guest-systemd/$unit\"",
        "sysinit.target.wants/cats-mount-propagation.service",
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
        "cats-mount-propagation.service",
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
            "cats-mount-propagation.service",
            &[
                "DefaultDependencies=no",
                "Before=cats-grow-root.service cats-network.service cats-guest-agent.service sysinit.target",
                "ExecStart=/bin/mount --make-rprivate /",
            ][..],
        ),
        (
            "cats-grow-root.service",
            &[
                "Requires=cats-mount-propagation.service",
                "After=cats-mount-propagation.service",
                "After=systemd-remount-fs.service",
                "Before=cats-guest-agent.service",
                "ExecStart=/sbin/resize2fs /dev/vda",
            ][..],
        ),
        (
            "cats-network.service",
            &[
                "Requires=cats-mount-propagation.service",
                "After=cats-mount-propagation.service",
                "After=systemd-remount-fs.service",
                "Before=cats-guest-agent.service network.target",
                "ExecStart=/usr/bin/cats-network-setup",
            ][..],
        ),
        (
            "cats-guest-agent.service",
            &[
                "Requires=cats-mount-propagation.service cats-grow-root.service cats-network.service",
                "After=cats-mount-propagation.service cats-grow-root.service cats-network.service systemd-remount-fs.service",
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

#[cfg(unix)]
#[test]
fn guest_image_resolver_is_readable_under_a_restrictive_caller_umask() {
    use std::os::unix::fs::PermissionsExt;

    let builder = read_workspace_file("deploy/metal/build-guest-image.sh");
    let resolver_section = builder
        .split_once("# Keep DNS independent")
        .and_then(|(_, rest)| rest.split_once("# Keep generic Ubuntu background work"))
        .map(|(section, _)| section)
        .expect("Guest resolver build section");

    let temp = tempfile::tempdir().expect("temporary Guest root fixture");
    std::fs::create_dir_all(temp.path().join("etc")).expect("create Guest etc directory");
    let output = std::process::Command::new("sh")
        .args(["-eu", "-c"])
        .arg(format!(
            "umask 077\n# Keep DNS independent{resolver_section}"
        ))
        .env("RF", temp.path())
        .output()
        .expect("run Guest resolver build section");
    assert!(
        output.status.success(),
        "Guest resolver build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mode = std::fs::metadata(temp.path().join("etc/resolv.conf"))
        .expect("stat Guest resolver")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o644,
        "unprivileged Guest programs such as APT's _apt worker must be able to read resolv.conf"
    );
}

#[test]
fn metal_acceptance_covers_systemd_service_lifecycle() {
    let text = read_workspace_file("deploy/metal/e2e.sh");
    for required in [
        "guest uses systemd as PID 1",
        "--no-auto-suspend",
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

#[test]
fn metal_acceptance_drives_real_mount_propagation_and_postgresql() {
    let text = read_workspace_file("deploy/metal/guest-mount-propagation-e2e.sh");
    for required in [
        "mount --rbind /dev \"$old_root/dev\"",
        "mount --rbind /dev \"$new_root/dev\"",
        "findmnt -Rrn -o TARGET",
        "umount -l \"$mounted\"",
        "stat -c '%a %u:%g %n'",
        "chroot --userspec=\"$postgres_uid:$postgres_gid\"",
        "$postgres_bin_dir/postgres\" --version",
        "start_cluster \"$old_root\"",
        "stop_cluster \"$old_root\"",
        "start_cluster \"$new_root\"",
        "stop_cluster \"$new_root\"",
    ] {
        assert!(
            text.contains(required),
            "metal mount-propagation acceptance lost real oracle {required:?}"
        );
    }

    let driver = read_workspace_file("deploy/metal/mount-propagation-e2e.sh");
    for required in [
        "--expires-in 21600",
        "policy-rc.d",
        "postgresql-17",
        "--stdin-file \"$guest_probe\"",
        "\"$CATS\" destroy \"$cat_name\"",
    ] {
        assert!(
            driver.contains(required),
            "metal mount-propagation acceptance driver lost fragment {required:?}"
        );
    }
}

#[test]
fn production_worker_bundle_updates_an_idle_guest_seed_before_restart() {
    let dockerignore = read_workspace_file(".dockerignore");
    for required in [
        "!deploy/metal/guest-systemd/",
        "!deploy/metal/guest-systemd/**",
    ] {
        assert!(
            dockerignore.lines().any(|line| line == required),
            "worker artifact build context lost guest units allowlist {required:?}"
        );
    }

    let dockerfile = read_workspace_file("deploy/aws/Dockerfile.worker-artifact");
    let installer = read_workspace_file("deploy/aws/metal/install-worker.sh");
    let deployment =
        read_workspace_file("deploy/aws/terraform/modules/metal-worker-deployment/main.tf");
    let manual_verifier = read_workspace_file("deploy/aws/tools/verify-manual-release.py");
    let manual_fixture = read_workspace_file("deploy/aws/tools/manual-release-fixture.py");
    assert_eq!(
        dockerfile
            .matches("COPY --from=builder /out/cats /cats")
            .count(),
        1,
        "worker artifact must publish exactly one Host-local cats provisioner binary"
    );
    assert_eq!(
        installer
            .matches(
                "install -m 0755 \"$CATS_REPO/target/release/cats\" \"$CATS_PREFIX/bin/cats\"",
            )
            .count(),
        1,
        "metal installer must install exactly one Host-local cats provisioner binary"
    );
    assert_eq!(
        deployment
            .matches("install -D -m 0755 \"$stage_path/cats\" \"${var.install_root}/bin/cats\"",)
            .count(),
        1,
        "Terraform worker transaction must install the bundled cats provisioner binary"
    );
    assert_eq!(
        manual_verifier.matches("    \"cats\",").count(),
        2,
        "manual verifier must classify cats as exactly one required executable member"
    );
    assert_eq!(
        manual_fixture.matches("    \"cats\",").count(),
        2,
        "manual verifier fixture must mirror cats in its file and executable sets"
    );
    for executable_copy in [
        "COPY --chmod=0755 deploy/aws/metal/install-guest-runtime-release.sh /out/install-guest-runtime-release.sh",
        "COPY --from=builder --chmod=0755 /out/install-guest-runtime-release.sh /install-guest-runtime-release.sh",
        "COPY --chmod=0755 deploy/aws/metal/worker-deployment-transaction.sh /out/worker-deployment-transaction.sh",
        "COPY --from=builder --chmod=0755 /out/worker-deployment-transaction.sh /worker-deployment-transaction.sh",
    ] {
        assert!(
            dockerfile.contains(executable_copy),
            "worker artifact lost executable installer mode {executable_copy:?}"
        );
    }
    for required in [
        "COPY --from=builder /out/cats-vmm-launcher /cats-vmm-launcher",
        "COPY deploy/aws/metal/update-guest-seed.sh /out/update-guest-seed.sh",
        "COPY deploy/aws/metal/require-idle-worker.sh /out/require-idle-worker.sh",
        "COPY deploy/metal/guest-systemd /out/guest-systemd",
        "COPY --from=builder /out/update-guest-seed.sh /update-guest-seed.sh",
        "COPY --from=builder /out/require-idle-worker.sh /require-idle-worker.sh",
        "COPY --from=builder /out/guest-systemd /guest-systemd",
    ] {
        assert!(
            dockerfile.contains(required),
            "worker artifact lost guest-seed payload fragment {required:?}"
        );
    }

    let early_idle_guard = deployment
        .find(
            "\"$stage_path/require-idle-worker.sh\" \"$metering_root\" \"${var.install_root}/bin\"",
        )
        .expect("worker deployment rejects active Cat processes and live runtime binaries");
    let first_install = deployment
        .find("install -D -m 0755 \"$stage_path/cats-noded\"")
        .expect("worker deployment installs cats-noded");
    let launcher_install = deployment
        .find("install -D -m 0755 \"$stage_path/cats-vmm-launcher\"")
        .expect("worker deployment installs the fixed VMM launcher");
    let release_verify = deployment
        .find("install-guest-runtime-release.sh\" verify")
        .expect("worker deployment verifies the shared Guest release");
    let update = deployment
        .find("# Replace the golden RootDisk while the worker remains stopped.")
        .expect("worker deployment has the guest-seed update phase");
    let deployment_lock = deployment
        .find("cats_acquire_worker_deployment_lock")
        .expect("worker deployment acquires its Host-global lock");
    let locked_metering = deployment[deployment_lock..]
        .find("metering_root=\"$(cats_worker_metering_root cats-worker)\"")
        .map(|offset| deployment_lock + offset)
        .expect("worker deployment recomputes its metering cgroup under the lock");
    let locked_idle_guard = deployment[locked_metering..]
        .find(
            "\"$stage_path/require-idle-worker.sh\" \"$metering_root\" \"${var.install_root}/bin\"",
        )
        .map(|offset| locked_metering + offset)
        .expect("worker deployment rechecks physical idle under the lock");
    let stop = deployment[locked_idle_guard..]
        .find("cats_gate_node_service cats-worker")
        .map(|offset| locked_idle_guard + offset)
        .expect("worker deployment masks and stops the idle worker");
    let prepare = deployment[stop..]
        .find("\"$release_installer\" prepare")
        .map(|offset| stop + offset)
        .expect("worker deployment retains the release journal");
    let start = deployment
        .find("systemctl start cats-worker")
        .expect("worker deployment starts the replacement worker");
    let authorize = deployment
        .find("cats_begin_candidate_lifetime cats-worker \"$release_installer\"")
        .expect("post-mutation worker start authorization and watchdog");
    assert!(
        release_verify < early_idle_guard
            && early_idle_guard < deployment_lock
            && deployment_lock < locked_metering
            && locked_metering < locked_idle_guard
            && locked_idle_guard < stop
            && stop < prepare
            && prepare < first_install
            && first_install < launcher_install
            && launcher_install < update
            && deployment[update..start].contains("\"${var.install_root}/bin/update-guest-seed\""),
        "worker must verify and guard the drain, stop, then replace release bytes before start"
    );
    assert!(
        stop < authorize && authorize < start,
        "worker must authorize only after stopping and mutating"
    );
    let readiness = deployment
        .find("cats_wait_for_registered_node cats-worker")
        .expect("registration-backed Node readiness");
    let commit = deployment
        .find("cats_commit_candidate \"$release_installer\"")
        .expect("release commit after readiness");
    assert!(start < readiness && readiness < commit);
    assert!(
        !deployment.contains("systemctl restart cats-worker"),
        "worker deployment must not abruptly restart active delegated cgroups"
    );

    for (path, service, unit_install, installed_installer) in [
        (
            "deploy/aws/terraform/modules/metal-worker-deployment/main.tf",
            "cats-worker",
            "install -m 0644 \"$stage_path/cats-worker.service\" /etc/systemd/system/cats-worker.service",
            "release_installer=\"${var.install_root}/bin/install-guest-runtime-release\"",
        ),
        (
            "deploy/aws/metal/install-worker.sh",
            "cats-worker",
            "install -m 0644 \"$CATS_REPO/deploy/aws/metal/cats-worker.service\"",
            "release_installer=\"$CATS_PREFIX/bin/install-guest-runtime-release\"",
        ),
        (
            "deploy/metal/install.sh",
            "cats-noded",
            "install -m 0644 \"$REPO/deploy/metal/systemd/cats-noded.service\"",
            "release_installer=\"$PREFIX/bin/install-guest-runtime-release\"",
        ),
    ] {
        let script = read_workspace_file(path);
        let gate = script
            .find(&format!("cats_gate_node_service {service}"))
            .unwrap_or_else(|| panic!("{path} lost its pre-journal runtime mask"));
        let recovery_unit = script[gate..]
            .find(unit_install)
            .map(|offset| gate + offset)
            .unwrap_or_else(|| panic!("{path} lost its recovery-gated Node unit install"));
        let fsync = script[recovery_unit..]
            .find("after-fsync-worker-recovery-gate")
            .map(|offset| recovery_unit + offset)
            .unwrap_or_else(|| panic!("{path} did not durably fsync the recovery gate"));
        let reload = script[fsync..]
            .find("after-recovery-gate-daemon-reload")
            .map(|offset| fsync + offset)
            .unwrap_or_else(|| panic!("{path} did not reload the recovery-gated unit"));
        let installed = script
            .find(installed_installer)
            .unwrap_or_else(|| panic!("{path} does not switch to the installed recovery helper"));
        let prepare = script[reload..]
            .find("\"$release_installer\" prepare")
            .map(|offset| reload + offset)
            .unwrap_or_else(|| panic!("{path} lost its activation prepare"));
        assert!(
            gate < recovery_unit
                && recovery_unit < fsync
                && fsync < reload
                && installed < prepare
                && reload < prepare,
            "{path} must make the runtime mask and reboot recovery gate durable before activation"
        );
    }
    let updater = read_workspace_file("deploy/aws/metal/update-guest-seed.sh");
    assert!(updater.contains("transaction_helper=/opt/cats/bin/worker-deployment-transaction"));
    assert!(!updater.contains("worker-deployment-transaction.sh"));
    for path in [
        "deploy/aws/terraform/modules/metal-worker-deployment/main.tf",
        "deploy/aws/metal/install-worker.sh",
        "deploy/metal/install.sh",
    ] {
        let script = read_workspace_file(path);
        assert!(
            script.contains("/bin/worker-deployment-transaction\"")
                || script.contains("/bin/worker-deployment-transaction'"),
            "{path} must install the updater helper under its canonical extensionless basename"
        );
    }
}

#[cfg(target_os = "linux")]
fn sha256_file(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("run sha256sum");
    assert!(output.status.success());
    let hex = String::from_utf8(output.stdout)
        .expect("sha256sum output is UTF-8")
        .split_whitespace()
        .next()
        .expect("sha256sum digest")
        .to_owned();
    format!("sha256:{hex}")
}

#[cfg(target_os = "linux")]
fn make_guest_release(root: &Path, marker: &str, with_initramfs: bool) {
    use std::os::unix::fs::PermissionsExt as _;

    let guest = root.join("guest");
    std::fs::create_dir_all(&guest).expect("create release fixture");
    let kernel = guest.join("vmlinuz");
    std::fs::write(&kernel, format!("kernel-{marker}")).expect("write release kernel fixture");
    std::fs::set_permissions(&kernel, std::fs::Permissions::from_mode(0o644)).unwrap();
    let kernel_digest = sha256_file(&kernel);
    let initramfs = if with_initramfs {
        let path = guest.join("initramfs.img");
        std::fs::write(&path, format!("initramfs-{marker}"))
            .expect("write release initramfs fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        Some((sha256_file(&path), std::fs::metadata(path).unwrap().len()))
    } else {
        None
    };
    let initramfs_digest = initramfs
        .as_ref()
        .map(|(digest, _)| format!("\"{digest}\""))
        .unwrap_or_else(|| "null".to_owned());
    let receipt = format!(
        "{{\"guest_agent_protocol_version\":1,\"initramfs_digest\":{initramfs_digest},\"kernel_cmdline\":\"console=ttyS0\",\"kernel_digest\":\"{kernel_digest}\",\"version\":1}}"
    );
    let receipt_path = root.join("guest-runtime-profile.v1.json");
    std::fs::write(&receipt_path, receipt).expect("write release receipt fixture");
    std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let receipt_digest = sha256_file(&receipt_path);
    let initramfs_entry = initramfs
        .as_ref()
        .map(|(digest, size)| {
            format!(
                "{{\"path\":\"guest/initramfs.img\",\"sha256\":\"{digest}\",\"size_bytes\":{size}}}"
            )
        })
        .unwrap_or_else(|| "null".to_owned());
    let manifest = format!(
        "{{\"guest_runtime_profile\":{{\"path\":\"guest-runtime-profile.v1.json\",\"sha256\":\"{receipt_digest}\",\"size_bytes\":{receipt_size}}},\"initramfs\":{initramfs_entry},\"kernel\":{{\"path\":\"guest/vmlinuz\",\"sha256\":\"{kernel_digest}\",\"size_bytes\":{kernel_size}}},\"version\":1}}",
        receipt_size = std::fs::metadata(&receipt_path).unwrap().len(),
        kernel_size = std::fs::metadata(&kernel).unwrap().len(),
    );
    let manifest_path = root.join("manifest.v1.json");
    std::fs::write(&manifest_path, manifest).expect("write release manifest fixture");
    std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[cfg(target_os = "linux")]
fn fault_injected_release_installer(
    template: &str,
    path: &Path,
    cats_root: &Path,
    uid: &str,
    gid: &str,
) {
    use std::os::unix::fs::PermissionsExt as _;

    let injected_probe = r#"crash_probe() {
  printf '%s\n' "$1" >> "${CATS_RELEASE_TRACE:?}"
  if [[ ${CATS_RELEASE_PAUSE_AT:-} == "$1" && ! -e ${CATS_RELEASE_PAUSED:-/dev/null} ]]; then
    printf '%s\n' "$1" > "${CATS_RELEASE_PAUSED:?}"
    while [[ ! -e ${CATS_RELEASE_CONTINUE:?} ]]; do
      sleep 0.01
    done
  fi
  probe_count=$(wc -l < "${CATS_RELEASE_TRACE:?}")
  if [[ ${CATS_RELEASE_KILL_AT_LABEL:-} == "$1" ]]; then
    kill -KILL $$
  fi
  if [[ $probe_count -eq ${CATS_RELEASE_KILL_AT:-0} ]]; then
    kill -KILL $$
  fi
}"#;
    let transformed = template
        .replace(
            "cats_root=/opt/cats",
            &format!("cats_root={}", cats_root.display()),
        )
        .replace("required_uid=0", &format!("required_uid={uid}"))
        .replace("required_gid=0", &format!("required_gid={gid}"))
        .replace(
            "deployment_lock_path=/run/lock/cats/worker-deployment.lock",
            &format!(
                "deployment_lock_path={}",
                cats_root.join("deployment.lock").display()
            ),
        )
        .replace("[[ $EUID -eq 0 ]]", "[[ $EUID -eq $required_uid ]]")
        .replace("crash_probe() { :; }", injected_probe);
    assert_ne!(
        transformed, template,
        "fault-injection transform did nothing"
    );
    std::fs::write(path, transformed).expect("write private installer copy");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(target_os = "linux")]
fn private_deployment_helper(template: &str, path: &Path, lock: &Path, uid: &str, gid: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    let transformed = template
        .replace(
            "/run/lock/cats/worker-deployment.lock",
            &lock.display().to_string(),
        )
        .replace(
            "CATS_WORKER_DEPLOYMENT_HELPER=/opt/cats/bin/worker-deployment-transaction",
            &format!("CATS_WORKER_DEPLOYMENT_HELPER={}", path.display()),
        )
        .replace("'0:0:600:1'", &format!("'{uid}:{gid}:600:1'"));
    assert_ne!(transformed, template);
    std::fs::write(path, transformed).expect("write private deployment helper");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct ReleaseInstallerContext<'a> {
    installer: &'a Path,
    fake_bin: &'a Path,
    trace: &'a Path,
    active: &'a Path,
    deployment_lock: &'a Path,
}

#[cfg(target_os = "linux")]
fn release_installer_command(
    context: ReleaseInstallerContext<'_>,
    mode: &str,
    source: &Path,
) -> Command {
    let mut path = context.fake_bin.as_os_str().to_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let mut command = Command::new("/bin/bash");
    command
        .args([
            "-c",
            "umask 077; exec 9>>\"$1\"; flock 9; export CATS_WORKER_DEPLOYMENT_LOCK_FD=9; case \"$3\" in authorize-start) /bin/bash \"$2\" authorize-start \"$CATS_TEST_TOKEN\" \"$CATS_TEST_PID\" \"$CATS_TEST_START\" && /bin/bash \"$2\" startup-recover ;; commit) /bin/bash \"$2\" bind-start \"$CATS_TEST_TOKEN\" \"$CATS_TEST_PID\" \"$CATS_TEST_START\" && /bin/bash \"$2\" commit \"$CATS_TEST_TOKEN\" \"$CATS_TEST_PID\" \"$CATS_TEST_START\" ;; *) exec /bin/bash \"$2\" \"$3\" \"$4\" ;; esac",
            "bash",
        ])
        .arg(context.deployment_lock)
        .arg(context.installer)
        .arg(mode)
        .arg(source)
        .env("PATH", path)
        .env("CATS_RELEASE_TRACE", context.trace)
        .env("CATS_FAKE_SERVICE_ACTIVE", context.active)
        .env("CATS_FAKE_MAIN_PID", std::process::id().to_string())
        .env("CATS_TEST_PID", std::process::id().to_string())
        .env("CATS_TEST_START", current_process_start_ticks())
        .env(
            "CATS_TEST_TOKEN",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
    command
}

#[cfg(target_os = "linux")]
fn run_release_installer(
    context: ReleaseInstallerContext<'_>,
    mode: &str,
    source: &Path,
    kill_at: Option<usize>,
) -> std::process::Output {
    let mut command = release_installer_command(context, mode, source);
    if let Some(kill_at) = kill_at {
        command.env("CATS_RELEASE_KILL_AT", kill_at.to_string());
    }
    command.output().expect("run release installer")
}

#[cfg(target_os = "linux")]
fn run_release_installer_at_label(
    context: ReleaseInstallerContext<'_>,
    mode: &str,
    source: &Path,
    kill_at_label: &str,
) -> std::process::Output {
    release_installer_command(context, mode, source)
        .env("CATS_RELEASE_KILL_AT_LABEL", kill_at_label)
        .output()
        .expect("run release installer with a named fault")
}

#[cfg(target_os = "linux")]
fn current_process_start_ticks() -> String {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", std::process::id()))
        .expect("read test process stat");
    stat.rsplit_once(") ")
        .expect("process stat command terminator")
        .1
        .split_whitespace()
        .nth(19)
        .expect("process start ticks")
        .to_owned()
}

#[cfg(target_os = "linux")]
fn run_startup_recover(
    installer: &Path,
    fake_bin: &Path,
    trace: &Path,
    active: &Path,
) -> std::process::Output {
    let mut path = fake_bin.as_os_str().to_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    Command::new(installer)
        .arg("startup-recover")
        .env("PATH", path)
        .env("CATS_RELEASE_TRACE", trace)
        .env("CATS_FAKE_SERVICE_ACTIVE", active)
        .output()
        .expect("run systemd startup recovery")
}

#[cfg(target_os = "linux")]
fn spawn_release_transaction(
    context: ReleaseInstallerContext<'_>,
    release: &Path,
    pause: (&str, &Path, &Path),
) -> DeploymentChild {
    let (pause_at, paused, continue_path) = pause;
    let mut path = context.fake_bin.as_os_str().to_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let child = Command::new("/bin/bash")
        .args([
            "-c",
            "set -euo pipefail; umask 077; exec 9>>\"$1\"; if ! flock -n 9; then : > \"$5\"; flock 9; fi; export CATS_WORKER_DEPLOYMENT_LOCK_FD=9; rm -f -- \"$4\"; owner_start=$(awk '{print $22}' /proc/$$/stat); token=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; \"$2\" prepare \"$3\"; \"$2\" authorize-start \"$token\" \"$$\" \"$owner_start\"; \"$2\" startup-recover; : > \"$4\"; \"$2\" bind-start \"$token\" \"$CATS_FAKE_MAIN_PID\" \"$CATS_TEST_START\"; \"$2\" commit \"$token\" \"$CATS_FAKE_MAIN_PID\" \"$CATS_TEST_START\"",
            "bash",
        ])
        .arg(context.deployment_lock)
        .arg(context.installer)
        .arg(release)
        .arg(context.active)
        .arg(paused.with_extension("lock-blocked"))
        .env("PATH", path)
        .env("CATS_RELEASE_TRACE", context.trace)
        .env("CATS_FAKE_SERVICE_ACTIVE", context.active)
        .env("CATS_FAKE_MAIN_PID", std::process::id().to_string())
        .env("CATS_TEST_START", current_process_start_ticks())
        .env("CATS_RELEASE_PAUSE_AT", pause_at)
        .env("CATS_RELEASE_PAUSED", paused)
        .env("CATS_RELEASE_CONTINUE", continue_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn release transaction");
    DeploymentChild(child)
}

#[cfg(target_os = "linux")]
struct DeploymentChild(std::process::Child);

#[cfg(target_os = "linux")]
impl std::ops::Deref for DeploymentChild {
    type Target = std::process::Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(target_os = "linux")]
impl std::ops::DerefMut for DeploymentChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(target_os = "linux")]
impl Drop for DeploymentChild {
    fn drop(&mut self) {
        if self.0.try_wait().is_ok_and(|status| status.is_none()) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_for_file(path: &Path, purpose: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {purpose}: {}",
            path.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn wait_for_success(child: &mut std::process::Child, purpose: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().expect("poll deployment child") {
            assert!(status.success(), "{purpose} failed with {status}");
            return;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("timed out waiting for {purpose}");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn assert_active_release(cats_root: &Path, expected: &Path) {
    for (active, source) in [
        ("guest/vmlinuz", "guest/vmlinuz"),
        (
            "release/guest-runtime-profile.v1.json",
            "guest-runtime-profile.v1.json",
        ),
        (
            "release/guest-runtime-release-manifest.v1.json",
            "manifest.v1.json",
        ),
    ] {
        assert_eq!(
            std::fs::read(cats_root.join(active)).unwrap(),
            std::fs::read(expected.join(source)).unwrap(),
            "active release member {active} is not from the expected complete set"
        );
    }
    let expected_initramfs = expected.join("guest/initramfs.img");
    let active_initramfs = cats_root.join("guest/initramfs.img");
    assert_eq!(active_initramfs.exists(), expected_initramfs.exists());
    if expected_initramfs.exists() {
        assert_eq!(
            std::fs::read(active_initramfs).unwrap(),
            std::fs::read(expected_initramfs).unwrap()
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn every_guest_release_durability_boundary_recovers_to_one_complete_set() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = tempfile::tempdir().expect("release crash fixture");
    let old = fixture.path().join("old");
    let new = fixture.path().join("new");
    make_guest_release(&old, "old", true);
    make_guest_release(&new, "new", false);
    let fake_bin = fixture.path().join("bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let systemctl = fake_bin.join("systemctl");
    std::fs::write(
        &systemctl,
        "#!/bin/sh\ncase \"$1:$3\" in\n  show:--property=LoadState) echo loaded ;;\n  show:--property=ActiveState) if [ -f \"$CATS_FAKE_SERVICE_ACTIVE\" ]; then echo active; else echo inactive; fi ;;\n  show:--property=MainPID) echo \"$CATS_FAKE_MAIN_PID\" ;;\n  is-active:cats-worker-deployment-watchdog.service) exit 0 ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let gid = String::from_utf8(Command::new("id").arg("-g").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let template = read_workspace_file("deploy/aws/metal/install-guest-runtime-release.sh");

    let baseline = fixture.path().join("baseline");
    std::fs::create_dir(&baseline).unwrap();
    let baseline_installer = baseline.join("installer");
    let baseline_root = baseline.join("cats");
    std::fs::create_dir(&baseline_root).unwrap();
    let baseline_trace = baseline.join("trace");
    let baseline_active = baseline.join("active");
    let baseline_lock = baseline_root.join("deployment.lock");
    fault_injected_release_installer(&template, &baseline_installer, &baseline_root, &uid, &gid);
    let baseline_context = ReleaseInstallerContext {
        installer: &baseline_installer,
        fake_bin: &fake_bin,
        trace: &baseline_trace,
        active: &baseline_active,
        deployment_lock: &baseline_lock,
    };
    let baseline_old = run_release_installer(baseline_context, "prepare", &old, None);
    assert!(
        baseline_old.status.success(),
        "known-positive old release install failed ({}): stdout={} stderr={}",
        baseline_old.status,
        String::from_utf8_lossy(&baseline_old.stdout),
        String::from_utf8_lossy(&baseline_old.stderr)
    );
    assert!(run_release_installer(
        baseline_context,
        "authorize-start",
        Path::new("unused"),
        None,
    )
    .status
    .success());
    std::fs::write(&baseline_active, "active").unwrap();
    assert!(
        run_release_installer(baseline_context, "commit", Path::new("unused"), None,)
            .status
            .success()
    );
    std::fs::remove_file(&baseline_active).unwrap();
    std::fs::write(&baseline_trace, "").unwrap();
    let baseline_new = run_release_installer(baseline_context, "prepare", &new, None);
    assert!(
        baseline_new.status.success(),
        "baseline activation failed: {}",
        String::from_utf8_lossy(&baseline_new.stderr)
    );
    assert!(run_release_installer(
        baseline_context,
        "authorize-start",
        Path::new("unused"),
        None,
    )
    .status
    .success());
    std::fs::write(&baseline_active, "active").unwrap();
    let baseline_commit =
        run_release_installer(baseline_context, "commit", Path::new("unused"), None);
    assert!(
        baseline_commit.status.success(),
        "known-positive commit failed: {}",
        String::from_utf8_lossy(&baseline_commit.stderr)
    );
    let boundary_count = std::fs::read_to_string(&baseline_trace)
        .unwrap()
        .lines()
        .count();
    assert!(
        boundary_count >= 25,
        "too few durability probes: {boundary_count}"
    );

    for kill_at in 1..=boundary_count {
        let case = fixture.path().join(format!("case-{kill_at}"));
        std::fs::create_dir(&case).unwrap();
        let installer = case.join("installer");
        let cats_root = case.join("cats");
        std::fs::create_dir(&cats_root).unwrap();
        let trace = case.join("trace");
        let active = case.join("active");
        let deployment_lock = cats_root.join("deployment.lock");
        fault_injected_release_installer(&template, &installer, &cats_root, &uid, &gid);
        let context = ReleaseInstallerContext {
            installer: &installer,
            fake_bin: &fake_bin,
            trace: &trace,
            active: &active,
            deployment_lock: &deployment_lock,
        };
        let old_install = run_release_installer(context, "prepare", &old, None);
        assert!(old_install.status.success());
        assert!(
            run_release_installer(context, "authorize-start", Path::new("unused"), None,)
                .status
                .success()
        );
        std::fs::write(&active, "active").unwrap();
        assert!(
            run_release_installer(context, "commit", Path::new("unused"), None,)
                .status
                .success()
        );
        std::fs::remove_file(&active).unwrap();
        std::fs::write(&trace, "").unwrap();

        let mut interrupted = run_release_installer(context, "prepare", &new, Some(kill_at));
        if interrupted.status.success() {
            interrupted = run_release_installer(
                context,
                "authorize-start",
                Path::new("unused"),
                Some(kill_at),
            );
        }
        if interrupted.status.success() {
            std::fs::write(&active, "active").unwrap();
            interrupted =
                run_release_installer(context, "commit", Path::new("unused"), Some(kill_at));
        }
        assert!(
            !interrupted.status.success(),
            "boundary {kill_at} did not interrupt activation"
        );
        // A retry may itself be interrupted before it can atomically replace
        // the retained journal. Kill it at its first durability boundary and
        // then require a third exact replay to converge. This catches the old
        // clear-then-prepare gap, where the second crash lost the only honest
        // recovery authority.
        let _ = std::fs::remove_file(&active);
        std::fs::write(&trace, "").unwrap();
        let interrupted_retry = run_release_installer(context, "prepare", &new, Some(1));
        assert!(
            !interrupted_retry.status.success(),
            "boundary {kill_at} did not survive a consecutive retry interruption"
        );
        // This is the observable outer restart boundary: the deployment first
        // stops the candidate, then prepare deterministically rolls back any
        // retained journal before replaying the same incoming release.
        let _ = std::fs::remove_file(&active);
        std::fs::write(&trace, "").unwrap();
        let recovered = run_release_installer(context, "prepare", &new, None);
        assert!(
            recovered.status.success(),
            "boundary {kill_at} did not recover: {}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        assert!(cats_root.join("releases/activation.v1").exists());
        assert!(
            run_release_installer(context, "authorize-start", Path::new("unused"), None,)
                .status
                .success()
        );
        std::fs::write(&active, "active").unwrap();
        assert!(
            run_release_installer(context, "commit", Path::new("unused"), None,)
                .status
                .success()
        );
        assert_eq!(
            std::fs::read(cats_root.join("guest/vmlinuz")).unwrap(),
            std::fs::read(new.join("guest/vmlinuz")).unwrap(),
            "boundary {kill_at} left a mixed kernel"
        );
        assert_eq!(
            std::fs::read(cats_root.join("release/guest-runtime-profile.v1.json")).unwrap(),
            std::fs::read(new.join("guest-runtime-profile.v1.json")).unwrap(),
            "boundary {kill_at} left a mixed receipt"
        );
        assert_eq!(
            std::fs::read(cats_root.join("release/guest-runtime-release-manifest.v1.json"))
                .unwrap(),
            std::fs::read(new.join("manifest.v1.json")).unwrap(),
            "boundary {kill_at} left a mixed manifest"
        );
        assert!(!cats_root.join("guest/initramfs.img").exists());
        assert!(!cats_root.join("releases/activation.v1").exists());
    }

    // Exercise the exact retry window that matters for journal replacement.
    // The first interruption leaves a durable new->old activation journal.
    // The retry recovers the old release, persists the complete candidate, and
    // then dies at the named boundary immediately before replacing that
    // journal. The retained authority must remain byte-for-byte unchanged.
    let case = fixture.path().join("case-before-journal-replace");
    std::fs::create_dir(&case).unwrap();
    let installer = case.join("installer");
    let cats_root = case.join("cats");
    std::fs::create_dir(&cats_root).unwrap();
    let trace = case.join("trace");
    let active = case.join("active");
    let deployment_lock = cats_root.join("deployment.lock");
    fault_injected_release_installer(&template, &installer, &cats_root, &uid, &gid);
    let context = ReleaseInstallerContext {
        installer: &installer,
        fake_bin: &fake_bin,
        trace: &trace,
        active: &active,
        deployment_lock: &deployment_lock,
    };
    assert!(run_release_installer(context, "prepare", &old, None)
        .status
        .success());
    assert!(
        run_release_installer(context, "authorize-start", Path::new("unused"), None)
            .status
            .success()
    );
    std::fs::write(&active, "active").unwrap();
    assert!(
        run_release_installer(context, "commit", Path::new("unused"), None)
            .status
            .success()
    );
    std::fs::remove_file(&active).unwrap();
    std::fs::write(&trace, "").unwrap();

    let first_interruption =
        run_release_installer_at_label(context, "prepare", &new, "active-copy:receipt");
    assert!(
        !first_interruption.status.success(),
        "first retry setup did not retain an uncommitted activation journal"
    );
    let journal_path = cats_root.join("releases/activation.v1");
    let retained_journal = std::fs::read(&journal_path)
        .expect("first interruption must leave its durable recovery journal");

    std::fs::write(&trace, "").unwrap();
    let second_interruption = run_release_installer_at_label(
        context,
        "prepare",
        &new,
        "activation-before-journal-replace",
    );
    assert!(
        !second_interruption.status.success(),
        "second retry did not die at the pre-replace journal boundary"
    );
    assert_eq!(
        std::fs::read(&journal_path).unwrap(),
        retained_journal,
        "a crash before journal replacement lost or rewrote the old recovery authority"
    );
    assert_eq!(
        std::fs::read_to_string(&trace).unwrap().lines().next_back(),
        Some("activation-before-journal-replace"),
        "the second SIGKILL must hit the exact named pre-replace boundary"
    );
    assert_active_release(&cats_root, &old);

    assert!(run_release_installer(context, "prepare", &new, None)
        .status
        .success());
    assert_active_release(&cats_root, &new);
}

#[cfg(target_os = "linux")]
#[test]
fn systemd_restart_rolls_back_uncommitted_candidate_and_stays_stopped() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = tempfile::tempdir().expect("startup recovery fixture");
    let old = fixture.path().join("old");
    let new = fixture.path().join("new");
    make_guest_release(&old, "old", true);
    make_guest_release(&new, "new", false);
    let fake_bin = fixture.path().join("bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let systemctl = fake_bin.join("systemctl");
    std::fs::write(
        &systemctl,
        "#!/bin/sh\ncase \"$1:$3\" in\n  show:--property=LoadState) echo loaded ;;\n  show:--property=ActiveState) if [ -f \"$CATS_FAKE_SERVICE_ACTIVE\" ]; then echo active; else echo inactive; fi ;;\n  show:--property=MainPID) echo \"$CATS_FAKE_MAIN_PID\" ;;\n  is-active:cats-worker-deployment-watchdog.service) exit 0 ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let gid = String::from_utf8(Command::new("id").arg("-g").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let cats_root = fixture.path().join("cats");
    std::fs::create_dir(&cats_root).unwrap();
    let installer = fixture.path().join("installer");
    let trace = fixture.path().join("trace");
    let active = fixture.path().join("service-active");
    let lock = cats_root.join("deployment.lock");
    fault_injected_release_installer(
        &read_workspace_file("deploy/aws/metal/install-guest-runtime-release.sh"),
        &installer,
        &cats_root,
        &uid,
        &gid,
    );
    let context = ReleaseInstallerContext {
        installer: &installer,
        fake_bin: &fake_bin,
        trace: &trace,
        active: &active,
        deployment_lock: &lock,
    };

    assert!(run_release_installer(context, "prepare", &old, None)
        .status
        .success());
    // Model a first/base rollout whose outer deployer dies immediately after
    // the initial journal becomes durable. On reboot the runtime mask is gone,
    // but a direct start executes the already-fsynced recovery-gated unit. It
    // must finish the one honest incoming set yet refuse to start it without a
    // new owner/readiness proof.
    let base_reboot = run_startup_recover(&installer, &fake_bin, &trace, &active);
    assert!(
        !base_reboot.status.success(),
        "a cached base unit must not bypass the first-rollout activation journal"
    );
    assert_active_release(&cats_root, &old);
    assert!(cats_root.join("releases/activation.v1").exists());
    assert!(run_release_installer(context, "prepare", &old, None)
        .status
        .success());
    assert!(
        run_release_installer(context, "authorize-start", Path::new("unused"), None,)
            .status
            .success()
    );
    std::fs::write(&active, "active").unwrap();
    assert!(
        run_release_installer(context, "commit", Path::new("unused"), None,)
            .status
            .success()
    );

    std::fs::remove_file(&active).unwrap();
    for (mode, source) in [
        ("prepare", new.as_path()),
        ("authorize-start", Path::new("unused")),
    ] {
        assert!(run_release_installer(context, mode, source, None)
            .status
            .success());
    }
    // The outer deployer has started and observed the candidate, then is
    // killed before commit. A reboot presents an inactive service and no live
    // outer lock to ExecStartPre.
    std::fs::write(&active, "active").unwrap();
    std::fs::remove_file(&active).unwrap();
    let recovery = run_startup_recover(&installer, &fake_bin, &trace, &active);
    assert!(
        !recovery.status.success(),
        "systemd must not start partial outer worker artifacts after rollback"
    );
    assert_active_release(&cats_root, &old);
    assert!(cats_root.join("releases/activation.v1").exists());
    assert!(!cats_root.join("releases/start-authorized.v1").exists());

    // A full outer transaction can now replay every worker artifact under the
    // same lock, replace the retained journal, prove readiness, and commit.
    for (mode, source) in [
        ("prepare", new.as_path()),
        ("authorize-start", Path::new("unused")),
    ] {
        assert!(run_release_installer(context, mode, source, None)
            .status
            .success());
    }
    std::fs::write(&active, "active").unwrap();
    assert!(
        run_release_installer(context, "commit", Path::new("unused"), None,)
            .status
            .success()
    );
    assert_active_release(&cats_root, &new);
    assert!(!cats_root.join("releases/activation.v1").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn owner_sigkill_or_main_identity_replacement_stops_and_rolls_back_candidate() {
    use std::os::unix::fs::PermissionsExt as _;

    let template = read_workspace_file("deploy/aws/metal/install-guest-runtime-release.sh");
    let helper_template = read_workspace_file("deploy/aws/metal/worker-deployment-transaction.sh");
    let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let gid = String::from_utf8(Command::new("id").arg("-g").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();

    for phase in [
        "after-check",
        "after-start",
        "after-readiness",
        "identity-replaced-before-commit",
    ] {
        let fixture = tempfile::tempdir().expect("candidate lifetime fixture");
        let old = fixture.path().join("old");
        let new = fixture.path().join("new");
        make_guest_release(&old, "old", true);
        make_guest_release(&new, "new", false);
        let cats_root = fixture.path().join("cats");
        let fake_bin = fixture.path().join("bin");
        std::fs::create_dir(&cats_root).unwrap();
        std::fs::create_dir(&fake_bin).unwrap();
        let installer = fixture.path().join("install-guest-runtime-release");
        let helper = fixture.path().join("worker-deployment-transaction");
        let lock = cats_root.join("deployment.lock");
        let active = fixture.path().join("service-active");
        let masked = fixture.path().join("service-masked");
        let trace = fixture.path().join("trace");
        let paused = fixture.path().join("outer-paused");
        let continue_path = fixture.path().join("outer-continue");
        let commit_succeeded = fixture.path().join("commit-succeeded");
        let watchdog_pid = fixture.path().join("watchdog-pid");
        let main_pid_file = fixture.path().join("main-pid");
        std::fs::write(&main_pid_file, std::process::id().to_string()).unwrap();
        fault_injected_release_installer(&template, &installer, &cats_root, &uid, &gid);
        private_deployment_helper(&helper_template, &helper, &lock, &uid, &gid);

        let systemctl = fake_bin.join("systemctl");
        std::fs::write(
            &systemctl,
            r#"#!/bin/sh
case "$1:$3" in
  show:--property=LoadState) echo loaded ;;
  show:--property=ActiveState)
    if [ -f "$CATS_FAKE_SERVICE_ACTIVE" ]; then echo active; else echo inactive; fi ;;
  show:--property=MainPID)
    if [ -f "${CATS_FAKE_MAIN_PID_FILE:-}" ]; then cat "$CATS_FAKE_MAIN_PID_FILE"; else echo "$CATS_FAKE_MAIN_PID"; fi ;;
  is-active:cats-worker-deployment-watchdog.service) exit 0 ;;
  mask:*) : > "$CATS_FAKE_SERVICE_MASKED" ;;
  stop:*) rm -f -- "$CATS_FAKE_SERVICE_ACTIVE" ;;
  *) exit 1 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        let curl = fake_bin.join("curl");
        std::fs::write(&curl, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
        let context = ReleaseInstallerContext {
            installer: &installer,
            fake_bin: &fake_bin,
            trace: &trace,
            active: &active,
            deployment_lock: &lock,
        };

        assert!(run_release_installer(context, "prepare", &old, None)
            .status
            .success());
        assert!(
            run_release_installer(context, "authorize-start", Path::new("unused"), None,)
                .status
                .success()
        );
        std::fs::write(&active, "active").unwrap();
        assert!(
            run_release_installer(context, "commit", Path::new("unused"), None)
                .status
                .success()
        );
        std::fs::remove_file(&active).unwrap();
        std::fs::write(&trace, "").unwrap();

        let mut command_path = fake_bin.as_os_str().to_os_string();
        command_path.push(":");
        command_path.push(std::env::var_os("PATH").unwrap_or_default());
        let outer_script = r#"
set -euo pipefail
exec 9>>"$1"
flock 9
export CATS_WORKER_DEPLOYMENT_LOCK_FD=9
. "$3"
owner_start=$(awk '{print $22}' "/proc/$$/stat")
token=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
"$2" prepare "$4"
setsid "$3" __watchdog cats-worker "$2" "$$" "$owner_start" "$token" \
  9>&- </dev/null >/dev/null 2>&1 &
printf '%s\n' "$!" > "$8"
"$2" authorize-start "$token" "$$" "$owner_start"
"$2" startup-recover
if [ "$7" = after-check ]; then : > "$6"; while :; do sleep 1; done; fi
: > "$5"
if [ "$7" = after-start ]; then : > "$6"; while :; do sleep 1; done; fi
"$2" bind-start "$token" "$CATS_FAKE_MAIN_PID" "$CATS_TEST_START"
CATS_WORKER_CANDIDATE_MAIN_PID=$CATS_FAKE_MAIN_PID
CATS_WORKER_CANDIDATE_MAIN_START=$CATS_TEST_START
export CATS_WORKER_CANDIDATE_MAIN_PID CATS_WORKER_CANDIDATE_MAIN_START
cats_wait_for_registered_node cats-worker
if [ "$7" = identity-replaced-before-commit ]; then
  : > "$6"
  while [ ! -e "$9" ]; do sleep 0.01; done
  cats_commit_candidate "$2"
  : > "${10}"
  exit 0
fi
: > "$6"; while :; do sleep 1; done
"#;
        let mut outer = DeploymentChild(
            Command::new("/bin/bash")
                .args(["-c", outer_script, "bash"])
                .arg(&lock)
                .arg(&installer)
                .arg(&helper)
                .arg(&new)
                .arg(&active)
                .arg(&paused)
                .arg(phase)
                .arg(&watchdog_pid)
                .arg(&continue_path)
                .arg(&commit_succeeded)
                .env("PATH", command_path)
                .env("CATS_RELEASE_TRACE", &trace)
                .env("CATS_FAKE_SERVICE_ACTIVE", &active)
                .env("CATS_FAKE_SERVICE_MASKED", &masked)
                .env("CATS_FAKE_MAIN_PID", std::process::id().to_string())
                .env("CATS_FAKE_MAIN_PID_FILE", &main_pid_file)
                .env("CATS_TEST_START", current_process_start_ticks())
                .spawn()
                .expect("spawn candidate deployment owner"),
        );
        wait_for_file(&paused, phase);
        wait_for_file(&watchdog_pid, "independent deployment watchdog");
        if phase == "identity-replaced-before-commit" {
            std::fs::write(&main_pid_file, "1").unwrap();
            std::fs::write(&continue_path, "continue").unwrap();
        } else {
            outer.kill().expect("SIGKILL outer deployment owner");
        }
        let killed = outer.wait().expect("wait for failed deployment owner");
        assert!(
            !killed.success(),
            "{phase} unexpectedly committed the candidate"
        );
        assert!(
            !commit_succeeded.exists(),
            "commit must reject a replacement MainPID/start identity"
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if masked.exists()
                && !active.exists()
                && Command::new("flock")
                    .arg("-n")
                    .arg(&lock)
                    .args(["-c", "true"])
                    .status()
                    .unwrap()
                    .success()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "watchdog did not fence and release the killed {phase} deployment"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_active_release(&cats_root, &old);
        assert!(cats_root.join("releases/activation.v1").exists());
        assert!(!cats_root.join("releases/start-authorized.v1").exists());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn guest_release_refuses_an_ambiguous_systemd_state_before_mutation() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = tempfile::tempdir().expect("systemd query failure fixture");
    let release = fixture.path().join("release-source");
    make_guest_release(&release, "candidate", false);
    let fake_bin = fixture.path().join("bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let systemctl = fake_bin.join("systemctl");
    std::fs::write(&systemctl, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let gid = String::from_utf8(Command::new("id").arg("-g").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let cats_root = fixture.path().join("cats");
    std::fs::create_dir(&cats_root).unwrap();
    let installer = fixture.path().join("installer");
    fault_injected_release_installer(
        &read_workspace_file("deploy/aws/metal/install-guest-runtime-release.sh"),
        &installer,
        &cats_root,
        &uid,
        &gid,
    );
    let trace = fixture.path().join("trace");
    let active = fixture.path().join("active");
    let lock = cats_root.join("deployment.lock");
    let context = ReleaseInstallerContext {
        installer: &installer,
        fake_bin: &fake_bin,
        trace: &trace,
        active: &active,
        deployment_lock: &lock,
    };
    let verified = run_release_installer(context, "verify", &release, None);
    assert!(
        verified.status.success(),
        "known-positive manifest probe failed: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let refused = run_release_installer(context, "prepare", &release, None);
    assert!(
        !refused.status.success(),
        "a systemd/D-Bus error must not be interpreted as an inactive worker"
    );
    assert!(!cats_root.join("releases").exists());
    assert!(!cats_root.join("release").exists());
    assert!(!cats_root.join("guest").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn overlapping_guest_release_transactions_serialize_journal_active_and_commit() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = tempfile::tempdir().expect("overlapping release fixture");
    let old = fixture.path().join("old");
    let new = fixture.path().join("new");
    make_guest_release(&old, "old", true);
    make_guest_release(&new, "new", false);
    let fake_bin = fixture.path().join("bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let systemctl = fake_bin.join("systemctl");
    std::fs::write(
        &systemctl,
        "#!/bin/sh\ncase \"$1:$3\" in\n  show:--property=LoadState) echo loaded ;;\n  show:--property=ActiveState) if [ -f \"$CATS_FAKE_SERVICE_ACTIVE\" ]; then echo active; else echo inactive; fi ;;\n  show:--property=MainPID) echo \"$CATS_FAKE_MAIN_PID\" ;;\n  is-active:cats-worker-deployment-watchdog.service) exit 0 ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let gid = String::from_utf8(Command::new("id").arg("-g").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let template = read_workspace_file("deploy/aws/metal/install-guest-runtime-release.sh");

    // These are the three distinct outer-transaction hazards: publishing the
    // durable journal, switching the final active completion marker, and
    // clearing the journal after readiness. Each case starts from a committed
    // old release and converges through two serialized deployments.
    for pause_at in [
        "activation-rename",
        "active-rename:manifest",
        "activation-remove",
    ] {
        let case = fixture.path().join(pause_at.replace(':', "-"));
        std::fs::create_dir(&case).unwrap();
        let installer = case.join("installer");
        let cats_root = case.join("cats");
        std::fs::create_dir(&cats_root).unwrap();
        let active = case.join("service-active");
        let lock = cats_root.join("deployment.lock");
        let bootstrap_trace = case.join("bootstrap-trace");
        fault_injected_release_installer(&template, &installer, &cats_root, &uid, &gid);
        let bootstrap_context = ReleaseInstallerContext {
            installer: &installer,
            fake_bin: &fake_bin,
            trace: &bootstrap_trace,
            active: &active,
            deployment_lock: &lock,
        };
        assert!(
            run_release_installer(bootstrap_context, "prepare", &old, None,)
                .status
                .success()
        );
        assert!(run_release_installer(
            bootstrap_context,
            "authorize-start",
            Path::new("unused"),
            None,
        )
        .status
        .success());
        std::fs::write(&active, "active").unwrap();
        assert!(
            run_release_installer(bootstrap_context, "commit", Path::new("unused"), None,)
                .status
                .success()
        );

        let first_trace = case.join("first-trace");
        let first_paused = case.join("first-paused");
        let first_continue = case.join("first-continue");
        let first_context = ReleaseInstallerContext {
            installer: &installer,
            fake_bin: &fake_bin,
            trace: &first_trace,
            active: &active,
            deployment_lock: &lock,
        };
        let mut first = spawn_release_transaction(
            first_context,
            &new,
            (pause_at, &first_paused, &first_continue),
        );
        wait_for_file(&first_paused, pause_at);
        assert_eq!(
            std::fs::read_to_string(&first_paused).unwrap().trim(),
            pause_at,
            "the positive control must reach the intended durability probe"
        );
        assert!(
            !Command::new("flock")
                .arg("-n")
                .arg(&lock)
                .args(["-c", "true"])
                .status()
                .unwrap()
                .success(),
            "the calibrated first transaction must hold the deployment lock"
        );

        let second_trace = case.join("second-trace");
        let second_paused = case.join("second-paused");
        let second_continue = case.join("second-continue");
        std::fs::write(&second_continue, "continue").unwrap();
        let second_context = ReleaseInstallerContext {
            installer: &installer,
            fake_bin: &fake_bin,
            trace: &second_trace,
            active: &active,
            deployment_lock: &lock,
        };
        let mut second = spawn_release_transaction(
            second_context,
            &old,
            ("never", &second_paused, &second_continue),
        );
        wait_for_file(
            &second_paused.with_extension("lock-blocked"),
            "second deployment to observe the occupied lock",
        );
        assert!(
            second.try_wait().unwrap().is_none(),
            "the overlapping deployment escaped the Host lock at {pause_at}"
        );
        assert!(
            !second_trace.exists() || std::fs::read(&second_trace).unwrap_or_default().is_empty(),
            "the overlapping deployment reached installer mutation at {pause_at}"
        );

        std::fs::write(&first_continue, "continue").unwrap();
        wait_for_success(&mut first, "first serialized deployment");
        wait_for_success(&mut second, "second serialized deployment");
        assert!(
            Command::new("flock")
                .arg("-n")
                .arg(&lock)
                .args(["-c", "true"])
                .status()
                .unwrap()
                .success(),
            "deployment lock probe must become positive after both transactions"
        );
        assert_active_release(&cats_root, &old);
        assert!(!cats_root.join("releases/activation.v1").exists());
    }
}

#[cfg(unix)]
#[test]
fn worker_release_refuses_active_cat_cgroups() {
    let temp = tempfile::tempdir().expect("temporary cgroup fixture");
    let metering_root = temp.path().join("metering");
    let active_cat = metering_root.join("metal-1/cat-active");
    std::fs::create_dir_all(&active_cat).expect("create cgroup fixture");
    let cgroup_procs = active_cat.join("cgroup.procs");
    std::fs::write(&cgroup_procs, "").expect("write empty cgroup");

    // An isolated bin root keeps the process-table scan away from whatever
    // the developer machine happens to run.
    let bin_root = temp.path().join("bin");
    std::fs::create_dir_all(&bin_root).expect("create bin fixture");

    let guard = workspace_root().join("deploy/aws/metal/require-idle-worker.sh");
    let idle = std::process::Command::new(&guard)
        .arg(&metering_root)
        .arg(&bin_root)
        .output()
        .expect("run idle worker guard");
    assert!(
        idle.status.success(),
        "empty metering cgroups must be releasable: {}",
        String::from_utf8_lossy(&idle.stderr)
    );

    std::fs::write(&cgroup_procs, "1818070\n").expect("write active cgroup");
    let active = std::process::Command::new(&guard)
        .arg(&metering_root)
        .arg(&bin_root)
        .output()
        .expect("run active worker guard");
    assert!(!active.status.success(), "active Cat must block release");
    let stderr = String::from_utf8_lossy(&active.stderr);
    assert!(
        stderr.contains("active Cat processes: 1818070")
            && stderr.contains("state=cordoned cats=0"),
        "guard must name the active PID and recovery contract: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn worker_release_refuses_live_runtime_binaries_outside_metering_cgroups() {
    use std::os::unix::fs::PermissionsExt as _;

    struct RuntimeChildren(Vec<std::process::Child>);

    impl Drop for RuntimeChildren {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn wait_until_process_table_has(expected: &[(u32, &Path)]) -> std::result::Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let output = std::process::Command::new("ps")
                .args(["-A", "-o", "pid=", "-o", "args="])
                .output()
                .map_err(|error| format!("snapshot process table: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "ps failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            let process_table = String::from_utf8_lossy(&output.stdout).into_owned();
            let all_visible = expected.iter().all(|(expected_pid, expected_argv0)| {
                process_table.lines().any(|line| {
                    let mut fields = line.split_whitespace();
                    let pid = fields.next().and_then(|value| value.parse::<u32>().ok());
                    let argv0 = fields.next();
                    pid == Some(*expected_pid) && argv0 == expected_argv0.to_str()
                })
            });
            if all_visible {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                let visibility = expected
                    .iter()
                    .map(|(pid, argv0)| {
                        let matching_line = process_table.lines().find(|line| {
                            line.split_whitespace()
                                .next()
                                .and_then(|value| value.parse::<u32>().ok())
                                == Some(*pid)
                        });
                        format!(
                            "pid={pid} argv0={} observed={matching_line:?}",
                            argv0.display()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(format!(
                    "runtime fixtures did not become observable before the deadline: {visibility}"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    let temp = tempfile::tempdir().expect("temporary runtime fixture");
    let metering_root = temp.path().join("metering");
    std::fs::create_dir_all(&metering_root).expect("create empty metering fixture");
    let bin_root = temp.path().join("bin");
    std::fs::create_dir_all(&bin_root).expect("create bin fixture");

    // cats-blockd and the short-lived launcher may be outside the metering
    // cgroup, while the VMM's name is longer than Linux comm. The guard must
    // catch all of them by their full argv[0] path (issue #98).
    let blockd_bin = bin_root.join("cats-blockd");
    let launcher_bin = bin_root.join("cats-vmm-launcher");
    let vmm_bin = bin_root.join("cloud-hypervisor");
    std::os::unix::fs::symlink("/bin/sleep", &blockd_bin).expect("stage fake blockd");
    std::os::unix::fs::symlink("/bin/sleep", &launcher_bin).expect("stage fake launcher");
    std::os::unix::fs::symlink("/bin/sleep", &vmm_bin).expect("stage fake vmm");
    let mut children = RuntimeChildren(Vec::new());
    children.0.push(
        std::process::Command::new(&blockd_bin)
            .arg("300")
            .spawn()
            .expect("spawn fake blockd"),
    );
    children.0.push(
        std::process::Command::new(&launcher_bin)
            .arg("300")
            .spawn()
            .expect("spawn fake launcher"),
    );
    children.0.push(
        std::process::Command::new(&vmm_bin)
            .arg("300")
            .spawn()
            .expect("spawn fake vmm"),
    );
    let blockd_pid = children.0[0].id();
    let launcher_pid = children.0[1].id();
    let vmm_pid = children.0[2].id();
    wait_until_process_table_has(&[
        (blockd_pid, &blockd_bin),
        (launcher_pid, &launcher_bin),
        (vmm_pid, &vmm_bin),
    ])
    .expect("runtime fixtures must be visible before exercising the guard");

    let guard = workspace_root().join("deploy/aws/metal/require-idle-worker.sh");
    let refused = std::process::Command::new(&guard)
        .arg(&metering_root)
        .arg(&bin_root)
        .output()
        .expect("run guard against live runtime binaries");

    assert!(
        !refused.status.success(),
        "a live runtime binary must block the release even with empty metering cgroups"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains(&format!("{blockd_pid}(cats-blockd)"))
            && stderr.contains(&format!("{launcher_pid}(cats-vmm-launcher)"))
            && stderr.contains(&format!("{vmm_pid}(cloud-hypervisor)"))
            && stderr.contains("unpublished writes"),
        "guard must name all runtime pids and the journal hazard: {stderr}"
    );

    for installer_path in [
        "deploy/aws/metal/install-worker.sh",
        "deploy/metal/install.sh",
    ] {
        let installer = read_workspace_file(installer_path);
        let early_guard = installer
            .find("require-idle-worker.sh\"")
            .unwrap_or_else(|| panic!("{installer_path} lost its physical idle guard"));
        let lock = installer
            .find("cats_acquire_worker_deployment_lock")
            .unwrap_or_else(|| panic!("{installer_path} lost its deployment lock"));
        let service = if installer_path == "deploy/metal/install.sh" {
            "cats-noded"
        } else {
            "cats-worker"
        };
        let locked_metering = installer[lock..]
            .find(&format!(
                "metering_root=$(cats_worker_metering_root {service})"
            ))
            .map(|offset| lock + offset)
            .unwrap_or_else(|| panic!("{installer_path} lost its locked metering recomputation"));
        let locked_guard = installer[locked_metering..]
            .find("require-idle-worker.sh\"")
            .map(|offset| locked_metering + offset)
            .unwrap_or_else(|| panic!("{installer_path} lost its locked physical idle guard"));
        let stop = installer[locked_guard..]
            .find("cats_gate_node_service")
            .map(|offset| locked_guard + offset)
            .unwrap_or_else(|| panic!("{installer_path} lost its masked stop boundary"));
        assert!(
            early_guard < lock
                && lock < locked_metering
                && locked_metering < locked_guard
                && locked_guard < stop,
            "{installer_path} must re-prove physical idle under the lock immediately before stopping"
        );
    }

    let stop_marker = temp.path().join("systemctl-stop-called");
    let fake_systemctl = bin_root.join("systemctl");
    std::fs::write(
        &fake_systemctl,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$CATS_STOP_MARKER\"\n",
    )
    .expect("write fake systemctl");
    std::fs::set_permissions(&fake_systemctl, std::fs::Permissions::from_mode(0o755))
        .expect("make fake systemctl executable");
    let mut command_path = bin_root.as_os_str().to_os_string();
    command_path.push(":");
    command_path.push(std::env::var_os("PATH").unwrap_or_default());
    let guarded_stop = std::process::Command::new("/bin/sh")
        .args([
            "-c",
            "set -e; \"$1\" \"$2\" \"$3\"; systemctl stop cats-worker",
            "sh",
        ])
        .arg(&guard)
        .arg(&metering_root)
        .arg(&bin_root)
        .env("PATH", command_path)
        .env("CATS_STOP_MARKER", &stop_marker)
        .output()
        .expect("run the manual-install pre-stop sequence");
    assert!(!guarded_stop.status.success());
    assert!(
        !stop_marker.exists(),
        "the physical idle failure must leave systemctl stop observably uncalled"
    );

    drop(children);

    let idle = std::process::Command::new(&guard)
        .arg(&metering_root)
        .arg(&bin_root)
        .output()
        .expect("run guard after the runtime binaries exited");
    assert!(
        idle.status.success(),
        "a node with no runtime processes must be releasable: {}",
        String::from_utf8_lossy(&idle.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn deployment_rechecks_physical_idle_after_waiting_for_the_host_lock() {
    use std::os::unix::fs::PermissionsExt as _;

    struct RuntimePidCleanup(PathBuf);

    impl Drop for RuntimePidCleanup {
        fn drop(&mut self) {
            if let Ok(pids) = std::fs::read_to_string(&self.0) {
                for pid in pids.split_whitespace() {
                    let _ = Command::new("kill")
                        .args(["-TERM", pid])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
            }
        }
    }

    let fixture = tempfile::tempdir().expect("deployment idle race fixture");
    let lock = fixture.path().join("worker-deployment.lock");
    let helper = fixture.path().join("worker-deployment-transaction");
    let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let gid = String::from_utf8(Command::new("id").arg("-g").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    private_deployment_helper(
        &read_workspace_file("deploy/aws/metal/worker-deployment-transaction.sh"),
        &helper,
        &lock,
        &uid,
        &gid,
    );

    let runtime_bin = fixture.path().join("runtime-bin");
    std::fs::create_dir(&runtime_bin).unwrap();
    let blockd = runtime_bin.join("cats-blockd");
    let vmm = runtime_bin.join("cloud-hypervisor");
    std::os::unix::fs::symlink("/bin/sleep", &blockd).unwrap();
    std::os::unix::fs::symlink("/bin/sleep", &vmm).unwrap();

    let cgroup_root = fixture.path().join("cgroup");
    std::fs::create_dir_all(cgroup_root.join("system.slice/cats-worker.service/metering")).unwrap();
    let fake_bin = fixture.path().join("fake-bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let findmnt = fake_bin.join("findmnt");
    std::fs::write(
        &findmnt,
        "#!/bin/sh\nprintf '%s\\n' \"$CATS_CGROUP_ROOT\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&findmnt, std::fs::Permissions::from_mode(0o755)).unwrap();
    let systemctl = fake_bin.join("systemctl");
    std::fs::write(
        &systemctl,
        "#!/bin/sh\ncase \"$1\" in\n  show) printf '%s\\n' /system.slice/cats-worker.service ;;\n  stop) : > \"$CATS_STOP_MARKER\" ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut command_path = fake_bin.as_os_str().to_os_string();
    command_path.push(":");
    command_path.push(std::env::var_os("PATH").unwrap_or_default());

    let a_locked = fixture.path().join("a-locked");
    let b_early = fixture.path().join("b-early-idle");
    let runtime_ready = fixture.path().join("a-runtime-ready");
    let release_a = fixture.path().join("release-a");
    let b_done = fixture.path().join("b-done");
    let runtime_pids = fixture.path().join("runtime-pids");
    let stop_marker = fixture.path().join("systemctl-stop-called");
    let b_stderr = fixture.path().join("b-stderr");

    let mut deployment_a = DeploymentChild(
        Command::new("/bin/bash")
            .args([
                "-c",
                r#"set -euo pipefail
. "$1"
cats_acquire_worker_deployment_lock
: > "$2"
while [[ ! -e "$3" ]]; do sleep 0.01; done
"$4" 300 & blockd_pid=$!
"$5" 300 & vmm_pid=$!
printf '%s\n%s\n' "$blockd_pid" "$vmm_pid" > "$6"
cleanup() {
  kill "$blockd_pid" "$vmm_pid" >/dev/null 2>&1 || true
  wait "$blockd_pid" "$vmm_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT
while ! ps -A -o args= | awk -v blockd="$4" -v vmm="$5" '
  $1 == blockd { blockd_seen = 1 }
  $1 == vmm { vmm_seen = 1 }
  END { exit !(blockd_seen && vmm_seen) }
'; do sleep 0.01; done
: > "$7"
while [[ ! -e "$8" ]]; do sleep 0.01; done
flock -u "$CATS_WORKER_DEPLOYMENT_LOCK_FD"
while [[ ! -e "$9" ]]; do sleep 0.01; done
"#,
                "bash",
            ])
            .arg(&helper)
            .arg(&a_locked)
            .arg(&b_early)
            .arg(&blockd)
            .arg(&vmm)
            .arg(&runtime_pids)
            .arg(&runtime_ready)
            .arg(&release_a)
            .arg(&b_done)
            .env("PATH", &command_path)
            .spawn()
            .expect("spawn deployment A"),
    );
    let _runtime_cleanup = RuntimePidCleanup(runtime_pids.clone());
    wait_for_file(&a_locked, "deployment A to hold the Host lock");

    let b_stderr_file = std::fs::File::create(&b_stderr).unwrap();
    let mut deployment_b = DeploymentChild(
        Command::new("/bin/bash")
            .args([
                "-c",
                r#"set -euo pipefail
trap ': > "$5"' EXIT
. "$1"
metering_root=$(cats_worker_metering_root cats-worker)
"$2" "$metering_root" "$3"
: > "$4"
cats_acquire_worker_deployment_lock
metering_root=$(cats_worker_metering_root cats-worker)
"$2" "$metering_root" "$3"
systemctl stop cats-worker
"#,
                "bash",
            ])
            .arg(&helper)
            .arg(workspace_root().join("deploy/aws/metal/require-idle-worker.sh"))
            .arg(&runtime_bin)
            .arg(&b_early)
            .arg(&b_done)
            .env("PATH", &command_path)
            .env("CATS_CGROUP_ROOT", &cgroup_root)
            .env("CATS_STOP_MARKER", &stop_marker)
            .stderr(b_stderr_file)
            .spawn()
            .expect("spawn deployment B"),
    );

    wait_for_file(&b_early, "deployment B to pass its unlocked idle preflight");
    wait_for_file(
        &runtime_ready,
        "deployment A runtime children to become process-table visible",
    );
    assert!(
        deployment_b.try_wait().unwrap().is_none(),
        "deployment B must still be waiting for deployment A's Host lock"
    );
    std::fs::write(&release_a, "release").unwrap();
    wait_for_file(&b_done, "deployment B to reject the locked idle recheck");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let b_status = loop {
        if let Some(status) = deployment_b.try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "deployment B did not exit after its locked idle rejection"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(
        !b_status.success(),
        "deployment B must fail when runtimes appear while it waits for the lock"
    );
    assert!(
        !stop_marker.exists(),
        "locked physical-idle rejection must leave systemctl stop observably uncalled"
    );
    let stderr = std::fs::read_to_string(&b_stderr).unwrap();
    assert!(
        stderr.contains("cats-blockd") && stderr.contains("cloud-hypervisor"),
        "locked recheck must name both new runtime processes: {stderr}"
    );
    wait_for_success(&mut deployment_a, "deployment A runtime owner");
}

#[cfg(target_os = "linux")]
#[test]
fn worker_release_atomically_updates_the_cloud_hypervisor_guest_seed() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary deployment fixture");
    let old_root = temp.path().join("old-root");
    for directory in [
        "usr/bin",
        "etc/systemd/system/sysinit.target.wants",
        "etc/systemd/system",
    ] {
        std::fs::create_dir_all(old_root.join(directory)).expect("create seed directory");
    }
    std::fs::write(old_root.join("usr/bin/cats-guest-agent"), b"old-agent")
        .expect("write old guest agent");
    std::fs::write(old_root.join("etc/resolv.conf"), b"nameserver 1.1.1.1\n")
        .expect("write restrictive Guest resolver");
    let mut resolver_permissions = std::fs::metadata(old_root.join("etc/resolv.conf"))
        .expect("read Guest resolver metadata")
        .permissions();
    resolver_permissions.set_mode(0o600);
    std::fs::set_permissions(old_root.join("etc/resolv.conf"), resolver_permissions)
        .expect("make Guest resolver restrictive");

    let seed = temp.path().join("rootfs.ext4");
    let seed_file = std::fs::File::create(&seed).expect("create seed image");
    seed_file
        .set_len(32 * 1024 * 1024)
        .expect("size seed image");
    let mkfs = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-d"])
        .arg(&old_root)
        .arg(&seed)
        .status()
        .expect("run mkfs.ext4");
    assert!(mkfs.success(), "mkfs.ext4 failed");

    let new_agent = temp.path().join("cats-guest-agent");
    std::fs::write(&new_agent, b"new-agent").expect("write new guest agent");
    let mut permissions = std::fs::metadata(&new_agent)
        .expect("read new guest agent metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&new_agent, permissions).expect("make guest agent executable");

    let updater_template = read_workspace_file("deploy/aws/metal/update-guest-seed.sh");
    let helper_template = read_workspace_file("deploy/aws/metal/worker-deployment-transaction.sh");
    let bundle = temp.path().join("worker-bundle");
    let install_bin = temp.path().join("installed/bin");
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::create_dir_all(&install_bin).unwrap();
    let bundled_updater = bundle.join("update-guest-seed.sh");
    let bundled_helper = bundle.join("worker-deployment-transaction.sh");
    let updater = install_bin.join("update-guest-seed");
    let helper = install_bin.join("worker-deployment-transaction");
    let lock = temp.path().join("deployment.lock");
    let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let gid = String::from_utf8(Command::new("id").arg("-g").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let helper_source = helper_template
        .replace(
            "/run/lock/cats/worker-deployment.lock",
            &lock.display().to_string(),
        )
        .replace("'0:0:600:1'", &format!("'{uid}:{gid}:600:1'"));
    std::fs::write(&bundled_helper, helper_source).unwrap();
    std::fs::write(
        &bundled_updater,
        updater_template.replace(
            "/opt/cats/bin/worker-deployment-transaction",
            &helper.display().to_string(),
        ),
    )
    .unwrap();
    for (source, installed) in [(&bundled_updater, &updater), (&bundled_helper, &helper)] {
        let install = Command::new("install")
            .args(["-m", "0755"])
            .arg(source)
            .arg(installed)
            .status()
            .expect("install worker bundle executable");
        assert!(install.success());
    }
    assert!(
        std::fs::read_to_string(&updater)
            .unwrap()
            .contains(&format!("transaction_helper={}", helper.display())),
        "bundle installation must leave the updater and helper on the same canonical basename contract"
    );
    let fake_bin = temp.path().join("bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let systemctl = fake_bin.join("systemctl");
    std::fs::write(
        &systemctl,
        "#!/bin/sh\ncase \"$1:$3\" in\n  show:--property=LoadState) echo loaded ;;\n  show:--property=ActiveState) echo inactive ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut command_path = fake_bin.as_os_str().to_os_string();
    command_path.push(":");
    command_path.push(std::env::var_os("PATH").unwrap_or_default());
    let units = workspace_root().join("deploy/metal/guest-systemd");
    let unlocked = Command::new(&updater)
        .arg(&seed)
        .arg(&new_agent)
        .arg(&units)
        .env("PATH", &command_path)
        .output()
        .expect("run updater without transaction lock");
    assert!(
        !unlocked.status.success(),
        "the installed seed updater must not be an independent mutation authority"
    );
    for pass in 0..2 {
        let output = Command::new("/bin/bash")
            .args([
                "-c",
                "umask 077; exec 9>>\"$1\"; flock 9; export CATS_WORKER_DEPLOYMENT_LOCK_FD=9; exec \"$2\" \"$3\" \"$4\" \"$5\"",
                "bash",
            ])
            .arg(&lock)
            .arg(&updater)
            .arg(&seed)
            .arg(&new_agent)
            .arg(&units)
            .env("PATH", &command_path)
            .output()
            .unwrap_or_else(|error| panic!("run seed updater pass {pass}: {error}"));
        assert!(
            output.status.success(),
            "seed updater pass {pass} failed: stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let dumped_agent = temp.path().join("dumped-agent");
    let dump_request = format!("dump /usr/bin/cats-guest-agent {}", dumped_agent.display());
    let dump = Command::new("debugfs")
        .args(["-R", &dump_request])
        .arg(&seed)
        .output()
        .expect("dump updated guest agent");
    assert!(
        dump.status.success(),
        "debugfs dump failed: {}",
        String::from_utf8_lossy(&dump.stderr)
    );
    assert_eq!(
        std::fs::read(&dumped_agent).expect("read dumped guest agent"),
        b"new-agent"
    );

    let resolver_stat = Command::new("debugfs")
        .args(["-R", "stat /etc/resolv.conf"])
        .arg(&seed)
        .output()
        .expect("stat updated Guest resolver");
    let resolver_stat_output = String::from_utf8_lossy(&resolver_stat.stdout);
    assert!(
        resolver_stat.status.success() && resolver_stat_output.contains("Mode:  0644"),
        "Guest resolver mode is wrong: stdout={resolver_stat_output:?}, stderr={:?}",
        String::from_utf8_lossy(&resolver_stat.stderr)
    );

    let stat = Command::new("debugfs")
        .args([
            "-R",
            "stat /etc/systemd/system/sysinit.target.wants/cats-mount-propagation.service",
        ])
        .arg(&seed)
        .output()
        .expect("stat mount-propagation symlink");
    let stat_output = String::from_utf8_lossy(&stat.stdout);
    assert!(
        stat.status.success()
            && stat_output.contains("Type: symlink")
            && stat_output.contains("../cats-mount-propagation.service"),
        "mount-propagation symlink is wrong: stdout={stat_output:?}, stderr={:?}",
        String::from_utf8_lossy(&stat.stderr)
    );

    assert!(
        seed.with_extension("ext4.previous").is_file(),
        "updater did not preserve the previous seed"
    );
}
