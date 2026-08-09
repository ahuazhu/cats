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
fn node_agent_restart_requires_a_drained_idle_node() {
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
        assert!(
            kill_modes.is_empty(),
            "{unit} must retain systemd's control-group default while V1 cannot safely preserve and re-adopt every child runtime across an agent stop; found {kill_modes:?}"
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
    let later_restart_guard = metal_readme
        .find("state=cordoned cats=0 orphans=0")
        .expect("metal restart instructions require an idle drained node");
    assert!(
        first_install < restart && restart < later_restart_guard,
        "metal restart instructions must limit the direct command to first install and then document the drain/idle guard"
    );
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
        variables.contains("metal_worker_instance_count = 2"),
        "the production example must retain worker capacity after one bare-metal host is lost"
    );
    assert!(
        variables.contains("metal_worker_names = [\"cats-metal-2\", \"cats-metal-1\"]"),
        "the imported cats-metal-2 must stay at index 0 while the second stable identity is appended"
    );

    let platform = read_workspace_file("deploy/aws/terraform/stacks/platform/main.tf")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        platform.contains(
            "subnet_id = module.network.private_subnet_ids[count.index % length(module.network.private_subnet_ids)]"
        ),
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

    let deployment =
        read_workspace_file("deploy/aws/terraform/modules/metal-worker-deployment/main.tf");
    let idle_guard = deployment
        .find(
            "\"$stage_path/require-idle-worker.sh\" \"$metering_root\" \"${var.install_root}/bin\"",
        )
        .expect("worker deployment rejects active Cat processes and live runtime binaries");
    let first_install = deployment
        .find("install -D -m 0755 \"$stage_path/cats-noded\"")
        .expect("worker deployment installs cats-noded");
    let release_verify = deployment
        .find("install-guest-runtime-release.sh\" verify")
        .expect("worker deployment verifies the shared Guest release");
    let update = deployment
        .find("# Replace the golden RootDisk while the worker remains stopped.")
        .expect("worker deployment has the guest-seed update phase");
    let deployment_lock = deployment
        .find("cats_acquire_worker_deployment_lock")
        .expect("worker deployment acquires its Host-global lock");
    let stop = deployment[deployment_lock..]
        .find("cats_stop_node_service cats-worker")
        .map(|offset| deployment_lock + offset)
        .expect("worker deployment stops the idle worker");
    let prepare = deployment[stop..]
        .find("\"$release_installer\" prepare")
        .map(|offset| stop + offset)
        .expect("worker deployment retains the release journal");
    let start = deployment
        .find("systemctl start cats-worker")
        .expect("worker deployment starts the replacement worker");
    let authorize = deployment
        .find("\"$release_installer\" authorize-start")
        .expect("post-mutation worker start authorization");
    assert!(
        release_verify < idle_guard
            && idle_guard < deployment_lock
            && deployment_lock < stop
            && stop < prepare
            && prepare < first_install
            && first_install < update
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
        .find("\"$release_installer\" commit")
        .expect("release commit after readiness");
    assert!(start < readiness && readiness < commit);
    assert!(
        !deployment.contains("systemctl restart cats-worker"),
        "worker deployment must not abruptly restart active delegated cgroups"
    );
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
#[derive(Clone, Copy)]
struct ReleaseInstallerContext<'a> {
    installer: &'a Path,
    fake_bin: &'a Path,
    trace: &'a Path,
    active: &'a Path,
    deployment_lock: &'a Path,
}

#[cfg(target_os = "linux")]
fn run_release_installer(
    context: ReleaseInstallerContext<'_>,
    mode: &str,
    source: &Path,
    kill_at: Option<usize>,
) -> std::process::Output {
    let mut path = context.fake_bin.as_os_str().to_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let mut command = Command::new("/bin/bash");
    command
        .args([
            "-c",
            "umask 077; exec 9>>\"$1\"; flock 9; export CATS_WORKER_DEPLOYMENT_LOCK_FD=9; exec /bin/bash \"$2\" \"$3\" \"$4\"",
            "bash",
        ])
        .arg(context.deployment_lock)
        .arg(context.installer)
        .arg(mode)
        .arg(source)
        .env("PATH", path)
        .env("CATS_RELEASE_TRACE", context.trace)
        .env("CATS_FAKE_SERVICE_ACTIVE", context.active);
    if let Some(kill_at) = kill_at {
        command.env("CATS_RELEASE_KILL_AT", kill_at.to_string());
    }
    command.output().expect("run release installer")
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
            "set -euo pipefail; umask 077; exec 9>>\"$1\"; if ! flock -n 9; then : > \"$5\"; flock 9; fi; export CATS_WORKER_DEPLOYMENT_LOCK_FD=9; rm -f -- \"$4\"; \"$2\" prepare \"$3\"; \"$2\" authorize-start; : > \"$4\"; \"$2\" commit",
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
        "#!/bin/sh\ncase \"$1:$3\" in\n  show:--property=LoadState) echo loaded ;;\n  show:--property=ActiveState) if [ -f \"$CATS_FAKE_SERVICE_ACTIVE\" ]; then echo active; else echo inactive; fi ;;\n  is-active:*) [ -f \"$CATS_FAKE_SERVICE_ACTIVE\" ] ;;\n  *) exit 1 ;;\nesac\n",
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
        // This is the observable outer restart boundary: the deployment first
        // stops the candidate, then prepare deterministically rolls back any
        // retained journal before replaying the same incoming release.
        let _ = std::fs::remove_file(&active);
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
        "#!/bin/sh\ncase \"$1:$3\" in\n  show:--property=LoadState) echo loaded ;;\n  show:--property=ActiveState) if [ -f \"$CATS_FAKE_SERVICE_ACTIVE\" ]; then echo active; else echo inactive; fi ;;\n  *) exit 1 ;;\nesac\n",
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

    for (mode, source) in [
        ("prepare", old.as_path()),
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
        "#!/bin/sh\ncase \"$1:$3\" in\n  show:--property=LoadState) echo loaded ;;\n  show:--property=ActiveState) if [ -f \"$CATS_FAKE_SERVICE_ACTIVE\" ]; then echo active; else echo inactive; fi ;;\n  is-active:*) [ -f \"$CATS_FAKE_SERVICE_ACTIVE\" ] ;;\n  *) exit 1 ;;\nesac\n",
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

    // A cats-blockd is not metered, so it lives outside every metering cgroup;
    // and the VMM's name is 16 characters, one past the kernel's 15-character
    // comm, so comm-based matching (`pgrep cloud-hypervisor`) never sees it.
    // The guard must catch both by their full argv[0] path (issue #98).
    let blockd_bin = bin_root.join("cats-blockd");
    let vmm_bin = bin_root.join("cloud-hypervisor");
    std::os::unix::fs::symlink("/bin/sleep", &blockd_bin).expect("stage fake blockd");
    std::os::unix::fs::symlink("/bin/sleep", &vmm_bin).expect("stage fake vmm");
    let mut children = RuntimeChildren(Vec::new());
    children.0.push(
        std::process::Command::new(&blockd_bin)
            .arg("300")
            .spawn()
            .expect("spawn fake blockd"),
    );
    children.0.push(
        std::process::Command::new(&vmm_bin)
            .arg("300")
            .spawn()
            .expect("spawn fake vmm"),
    );
    let blockd_pid = children.0[0].id();
    let vmm_pid = children.0[1].id();
    wait_until_process_table_has(&[(blockd_pid, &blockd_bin), (vmm_pid, &vmm_bin)])
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
            && stderr.contains(&format!("{vmm_pid}(cloud-hypervisor)"))
            && stderr.contains("unpublished writes"),
        "guard must name both runtime pids and the journal hazard: {stderr}"
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
    let updater = temp.path().join("update-guest-seed");
    let helper = temp.path().join("worker-deployment-transaction");
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
    std::fs::write(&helper, helper_source).unwrap();
    std::fs::write(
        &updater,
        updater_template.replace(
            "/opt/cats/bin/worker-deployment-transaction.sh",
            &helper.display().to_string(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&updater, std::fs::Permissions::from_mode(0o755)).unwrap();
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
