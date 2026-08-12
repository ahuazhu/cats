use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::io::Write;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

const SCHEMA_PATH: &str = "storage/src/authority.rs";
const SCHEMA_VERSION_PATTERN: &str = r"s/^pub[[:space:]]+const[[:space:]]+AUTHORITY_RELEASE_SCHEMA_VERSION:[[:space:]]+i64[[:space:]]+=[[:space:]]+([0-9]+);$/\1/p";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn read_workspace_file(path: &str) -> String {
    let path = workspace_root().join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("read {}: {error}", path.display());
    })
}

#[test]
fn production_platform_defaults_to_independent_az_dependencies() {
    let variables = read_workspace_file("deploy/aws/terraform/stacks/platform/variables.tf");
    let example =
        read_workspace_file("deploy/aws/terraform/stacks/platform/platform.tfvars.example");

    let assert_true_default = |source: &str, name: &str| {
        let declaration = format!("variable \"{name}\"");
        let block = source
            .split_once(&declaration)
            .and_then(|(_, rest)| rest.split_once("\n}"))
            .map(|(block, _)| block)
            .unwrap_or_else(|| panic!("missing Terraform variable {name}"));
        assert!(
            block
                .lines()
                .any(|line| line.trim() == "default     = true"),
            "{name} must fail over across availability zones by default"
        );
    };

    for (name, module_path, module_name) in [
        (
            "one_nat_gateway_per_az",
            "deploy/aws/terraform/modules/platform-network/variables.tf",
            "one_nat_gateway_per_az",
        ),
        (
            "database_multi_az",
            "deploy/aws/terraform/modules/platform-database/variables.tf",
            "multi_az",
        ),
    ] {
        assert_true_default(&variables, name);
        let module = read_workspace_file(module_path);
        assert_true_default(&module, module_name);

        let assignment = example.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == name).then(|| value.trim())
        });
        assert_eq!(
            assignment,
            Some("true"),
            "the production example must enable {name}"
        );
    }
}

#[test]
fn route_grant_private_key_reaches_only_control_plane_and_nodes_get_public_key() {
    let kubernetes = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    let control = kubernetes
        .split_once("resource \"kubernetes_deployment_v1\" \"control_plane\"")
        .and_then(|(_, rest)| rest.split_once("resource \"kubernetes_pod_disruption_budget_v1\""))
        .map(|(section, _)| section)
        .expect("control-plane Deployment section");
    assert!(
        !kubernetes.contains("resource \"kubernetes_deployment_v1\" \"gateway\""),
        "the V1 Gateway must remain undeployed during the v2 cutover"
    );
    for fragment in [
        "kubernetes_secret_v1.route_grant_signing",
        "CATS_ROUTE_GRANT_PRIVATE_KEY_FILE",
        "/etc/cats/route-grant/private.pem",
    ] {
        assert!(
            control.contains(fragment) || kubernetes.contains(fragment),
            "control-plane Route Grant delivery lost {fragment:?}"
        );
    }
    for fragment in [
        "CATS_ROUTE_GRANT_PUBLIC_KEY_FILE",
        "/etc/cats/route-grant/public.pem",
        "\"public.pem\"  = var.route_grant_public_key_pem",
    ] {
        assert!(
            control.contains(fragment) || kubernetes.contains(fragment),
            "control-plane startup pair verification lost {fragment:?}"
        );
    }

    let worker =
        read_workspace_file("deploy/aws/terraform/modules/metal-worker-deployment/main.tf");
    assert!(worker.contains("base64encode(var.route_grant_public_key_pem)"));
    assert!(worker.contains("/etc/cats/route-grant-public.pem"));
    assert!(worker.contains("installed_route_grant_key_fingerprint"));
    assert!(worker.contains("-outform DER"));
    for unit in [
        "deploy/aws/metal/cats-worker.service",
        "deploy/metal/systemd/cats-noded.service",
    ] {
        assert!(
            read_workspace_file(unit)
                .contains("--route-grant-public-key-file /etc/cats/route-grant-public.pem"),
            "{unit} does not give cats-noded its verification key"
        );
    }

    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    assert!(workflow.contains(
        "ROUTE_GRANT_PRIVATE_KEY_PEM_B64: ${{ secrets.ROUTE_GRANT_PRIVATE_KEY_PEM_B64 }}"
    ));
    assert!(workflow.contains("route-grant-private.pem"));
    assert!(workflow.contains("openssl pkey"));
    assert!(workflow.contains("^ED25519 Private-Key:"));
    assert!(workflow.contains("-pubout"));
    assert!(!workflow.contains("route-grant-public.sha256"));
    assert!(workflow.contains(
        "--rawfile route_grant_private_key_pem \"$RUNNER_TEMP/route-grant-private.pem\""
    ));
    assert!(workflow.contains("route_grant_private_key_pem: $route_grant_private_key_pem"));
    assert!(workflow
        .contains("--rawfile route_grant_public_key_pem \"$RUNNER_TEMP/route-grant-public.pem\""));
    assert!(workflow.contains("route_grant_public_key_pem: $route_grant_public_key_pem"));

    let dev = read_workspace_file("scripts/dev.sh");
    assert!(dev.contains("signed Agent-registration cutover"));
    assert!(dev.contains("provisioner-owned /etc/cats/identity"));
    assert!(!dev.contains("--node-id"));
    assert!(!dev.contains("--state-dir"));
}

#[test]
fn production_artifacts_remove_the_v1_gateway_and_shared_route_mirror() {
    for removed in [
        "deploy/aws/terraform/modules/route-cache-infrastructure/main.tf",
        "deploy/aws/terraform/modules/route-cache-infrastructure/variables.tf",
        "deploy/aws/terraform/modules/route-cache-infrastructure/outputs.tf",
        "deploy/aws/check-route-grant-nodes.sh",
        "deploy/metal/systemd/cats-gatewayd.service",
    ] {
        assert!(
            !workspace_root().join(removed).exists(),
            "legacy production artifact still exists: {removed}"
        );
    }

    for path in [
        "deploy/aws/terraform/modules/cats-kubernetes/main.tf",
        "deploy/aws/terraform/modules/cats-kubernetes/variables.tf",
        "deploy/aws/terraform/modules/cats-kubernetes/outputs.tf",
        "deploy/aws/terraform/stacks/production-application/main.tf",
        "deploy/aws/terraform/stacks/production-application/variables.tf",
        "deploy/aws/terraform/stacks/production-application/outputs.tf",
        "deploy/aws/terraform/stacks/production-infrastructure/main.tf",
        "deploy/aws/terraform/stacks/production-infrastructure/outputs.tf",
        ".github/workflows/deploy-production.yml",
        "deploy/aws/Dockerfile.control-plane",
    ] {
        let source = read_workspace_file(path);
        for forbidden in [
            "CATS_SHARED_ROUTE_CACHE_TABLE",
            "shared_route_cache_table",
            "ROUTE_CACHE_TABLE_NAME",
            "route_cache_infrastructure",
            "cats-gatewayd",
            "kubernetes_deployment_v1.gateway",
            "kubernetes_service_v1.gateway",
        ] {
            assert!(
                !source.contains(forbidden),
                "{path} still ships or deploys legacy Gateway surface {forbidden:?}"
            );
        }
    }

    let manifest = read_workspace_file("network/Cargo.toml");
    assert!(manifest.contains("legacy-test-harness"));
    assert!(!manifest.contains("aws-sdk-dynamodb"));
    assert!(!manifest.contains("aws-config"));

    let binary = read_workspace_file("network/src/main.rs");
    assert!(binary.contains("Route Grant v2 is not composed"));
    assert!(binary.contains("ExitCode::FAILURE"));
    for forbidden in [
        "cats_network::spawn",
        "/v1/routes/resolve",
        "/v1/routes/wake",
        "/v1/cats/",
        "CATS_SHARED_ROUTE_CACHE_TABLE",
        "READY ",
    ] {
        assert!(
            !binary.contains(forbidden),
            "default Gateway binary retained legacy behavior {forbidden:?}"
        );
    }

    let metal = read_workspace_file("deploy/metal/install.sh");
    assert!(metal.contains("cats_retire_legacy_gateway \\"));
    assert!(metal.contains("/etc/systemd/system/cats-gatewayd.service \\"));
    assert!(metal.contains("/etc/systemd/system/multi-user.target.wants/cats-gatewayd.service \\"));
    assert!(metal.contains("\"$PREFIX/bin/cats-gatewayd\""));
    assert!(!metal.contains("systemctl disable --now cats-gatewayd.service"));
    assert!(!metal.contains("cats cats-controld cats-noded cats-gatewayd"));
    assert!(!metal.contains("enable --now cats-controld cats-gatewayd"));
    assert!(!metal.contains("status cats-controld cats-gatewayd cats-noded"));

    let deployment = read_workspace_file("deploy/aws/metal/worker-deployment-transaction.sh");
    for expected in [
        "cats_retire_legacy_gateway()",
        "systemctl disable \"$service\"",
        "[ \"$load_state\" = not-found ]",
        "cats_stop_node_service \"$service\" || return 1",
        "cats_require_node_service_stopped \"$service\" || return 1",
        "rm -f -- \"$unit_file\" \"$wants_link\" \"$binary_file\"",
    ] {
        assert!(
            deployment.contains(expected),
            "legacy Gateway retirement lost {expected:?}"
        );
    }
    assert!(!deployment.contains("disable --now cats-gatewayd.service 2>/dev/null || true"));
}

#[cfg(unix)]
#[test]
fn legacy_gateway_retirement_fails_closed_before_removing_files() {
    let fixture = tempfile::tempdir().expect("legacy Gateway retirement fixture");
    let fake_bin = fixture.path().join("bin");
    std::fs::create_dir_all(&fake_bin).expect("create fake systemctl directory");
    let systemctl = fake_bin.join("systemctl");
    std::fs::write(
        &systemctl,
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$CATS_FAKE_SYSTEMCTL_TRACE"
case "$1" in
  disable)
    case "$CATS_FAKE_SYSTEMCTL_MODE" in
      absent|disable-fails-loaded) exit 1 ;;
      *) exit 0 ;;
    esac
    ;;
  stop)
    case "$CATS_FAKE_SYSTEMCTL_MODE" in
      absent|active-stop-fails) exit 1 ;;
      *) exit 0 ;;
    esac
    ;;
  show)
    property=""
    for argument in "$@"; do
      case "$argument" in
        --property=*) property=${argument#--property=} ;;
      esac
    done
    case "$property:$CATS_FAKE_SYSTEMCTL_MODE" in
      LoadState:absent) printf 'not-found\n' ;;
      LoadState:*) printf 'loaded\n' ;;
      ActiveState:active-after-stop) printf 'active\n' ;;
      ActiveState:*) printf 'inactive\n' ;;
      *) exit 64 ;;
    esac
    ;;
  *) exit 64 ;;
esac
"#,
    )
    .expect("write fake systemctl");
    let mut permissions = std::fs::metadata(&systemctl)
        .expect("fake systemctl metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&systemctl, permissions).expect("make fake systemctl executable");

    let helper = workspace_root().join("deploy/aws/metal/worker-deployment-transaction.sh");
    let inherited_path = std::env::var("PATH").expect("PATH");
    for (mode, succeeds, removes_files) in [
        ("stopped", true, true),
        ("absent", true, true),
        ("disable-fails-loaded", false, false),
        ("active-stop-fails", false, false),
        ("active-after-stop", false, false),
    ] {
        let case_dir = fixture.path().join(mode);
        let systemd_dir = case_dir.join("etc/systemd/system");
        let unit_file = systemd_dir.join("cats-gatewayd.service");
        let wants_link = systemd_dir.join("multi-user.target.wants/cats-gatewayd.service");
        let binary_file = case_dir.join("opt/cats/bin/cats-gatewayd");
        for path in [&unit_file, &wants_link, &binary_file] {
            std::fs::create_dir_all(path.parent().expect("artifact parent"))
                .expect("create legacy artifact parent");
            std::fs::write(path, b"legacy").expect("write legacy artifact");
        }
        let trace_file = case_dir.join("systemctl.trace");
        let output = Command::new("bash")
            .args([
                "-c",
                ". \"$1\"; cats_retire_legacy_gateway \"$2\" \"$3\" \"$4\"",
                "legacy-gateway-retirement-test",
            ])
            .arg(&helper)
            .arg(&unit_file)
            .arg(&wants_link)
            .arg(&binary_file)
            .env("CATS_FAKE_SYSTEMCTL_MODE", mode)
            .env("CATS_FAKE_SYSTEMCTL_TRACE", &trace_file)
            .env("PATH", format!("{}:{inherited_path}", fake_bin.display()))
            .output()
            .expect("run legacy Gateway retirement helper");
        assert_eq!(
            output.status.success(),
            succeeds,
            "unexpected {mode} result: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for path in [&unit_file, &wants_link, &binary_file] {
            assert_eq!(
                path.exists(),
                !removes_files,
                "{mode} left the wrong artifact state at {}",
                path.display()
            );
        }

        let trace = std::fs::read_to_string(&trace_file).expect("read systemctl trace");
        assert!(trace.contains("disable cats-gatewayd.service"));
        if mode == "disable-fails-loaded" {
            assert!(!trace.contains("stop cats-gatewayd.service"));
        } else {
            assert!(trace.contains("stop cats-gatewayd.service"));
        }
        if mode == "active-after-stop" {
            assert!(trace.contains("show cats-gatewayd.service --property=ActiveState --value"));
        }
    }
}

#[test]
fn control_plane_image_manifest_access_is_exact_and_read_only() {
    let identity = read_workspace_file("deploy/aws/terraform/modules/usage-infrastructure/main.tf");
    let manifest_policy = identity
        .split_once("data \"aws_iam_policy_document\" \"image_manifest_reader\"")
        .and_then(|(_, rest)| {
            rest.split_once("resource \"aws_iam_role_policy\" \"image_manifest_reader\"")
        })
        .map(|(section, _)| section)
        .expect("image manifest IAM policy");
    assert!(manifest_policy.contains("actions = [\"s3:GetObject\"]"));
    assert!(manifest_policy.contains("${var.chunkstore_prefix}/images/*/manifest.json"));
    for forbidden in [
        "s3:ListBucket",
        "s3:PutObject",
        "s3:DeleteObject",
        "/data/",
        "/volumes/",
    ] {
        assert!(
            !manifest_policy.contains(forbidden),
            "manifest reader gained forbidden scope {forbidden}"
        );
    }

    let kubernetes = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    let control = kubernetes
        .split_once("resource \"kubernetes_deployment_v1\" \"control_plane\"")
        .and_then(|(_, rest)| rest.split_once("resource \"kubernetes_pod_disruption_budget_v1\""))
        .map(|(section, _)| section)
        .expect("control-plane Deployment section");
    for expected in [
        "\"--object-store-adapter\"",
        "\"aws-s3\"",
        "bucket=${var.chunkstore_bucket_name}",
        "region=${var.chunkstore_region}",
        "prefix=${var.chunkstore_prefix}",
    ] {
        assert!(
            control.contains(expected),
            "control-plane manifest adapter lost {expected:?}"
        );
    }

    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    assert!(workflow.contains("CHUNKSTORE_BUCKET_NAME: ${{ vars.CHUNKSTORE_BUCKET_NAME }}"));
    assert!(workflow.contains("-var=\"chunkstore_bucket_name=$CHUNKSTORE_BUCKET_NAME\""));
}

#[test]
fn production_deploy_has_no_legacy_route_grant_admin_preflight() {
    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    for forbidden in [
        "Check Route Grant verifier compatibility",
        "/v1/admin/nodes",
        "route-grant-public.sha256",
        "check-route-grant-nodes.sh",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "production deploy retained legacy Route Grant preflight {forbidden:?}"
        );
    }
    assert!(
        !workspace_root()
            .join("deploy/aws/check-route-grant-nodes.sh")
            .exists(),
        "the unreachable V1 Node verifier must be removed with its workflow hook"
    );

    let initialize = workflow
        .find("- name: Initialize application state")
        .expect("application initialization step");
    let plan = workflow
        .find("- name: Plan production deployment")
        .expect("production plan step");
    let apply = workflow
        .find("- name: Apply reviewed plan")
        .expect("production apply step");
    assert!(
        initialize < plan && plan < apply,
        "removing the legacy preflight must preserve plan/apply ordering"
    );
}

#[test]
fn release_build_publishes_the_control_plane_runtime_target() {
    let workflow = read_workspace_file(".github/workflows/release.yml");
    let build = workflow
        .split_once("- name: Build and push")
        .and_then(|(_, rest)| rest.split_once("- name: Report image reference"))
        .map(|(step, _)| step)
        .expect("control-plane Buildx step");
    assert!(build.contains("file: deploy/aws/Dockerfile.control-plane"));
    assert!(build.contains("target: runtime"));

    let dockerfile = read_workspace_file("deploy/aws/Dockerfile.control-plane");
    let runtime = dockerfile
        .split_once("FROM debian:bookworm-slim AS runtime")
        .and_then(|(_, rest)| rest.split_once("FROM runtime AS credential-refresher"))
        .map(|(stage, _)| stage)
        .expect("dedicated control-plane runtime stage");
    assert!(runtime.contains("ENTRYPOINT [\"/usr/local/bin/cats-controld\"]"));
}

#[test]
fn route_grant_application_keeps_gateway_undeployed_until_v2() {
    let kubernetes = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    let control = kubernetes
        .split_once("resource \"kubernetes_deployment_v1\" \"control_plane\"")
        .and_then(|(_, rest)| rest.split_once("resource \"kubernetes_pod_disruption_budget_v1\""))
        .map(|(section, _)| section)
        .expect("control-plane Deployment section");
    assert!(
        control.contains("wait_for_rollout = true"),
        "Terraform must wait for the complete control-plane rollout"
    );
    assert!(
        !kubernetes.contains("resource \"kubernetes_deployment_v1\" \"gateway\""),
        "production must not deploy the legacy Gateway while v2 is incomplete"
    );
    assert!(
        !kubernetes.contains("endpoint_wildcard_host"),
        "production must not publish an Endpoint ingress route without the v2 Gateway"
    );
}

#[cfg(unix)]
fn ha_fixture_guard() -> std::sync::MutexGuard<'static, ()> {
    static FIXTURE_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    FIXTURE_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("HA fixture lock is not poisoned")
}

#[test]
fn production_deploy_extracts_versions_from_the_current_store_schema() {
    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    assert_eq!(
        workflow.matches(SCHEMA_PATH).count(),
        1,
        "production deployment must read the exact schema version from {SCHEMA_PATH}"
    );
    assert!(
        !workflow.contains("control-plane/src/store.rs"),
        "production deployment still refers to the pre-refactor Store module"
    );

    assert!(
        workflow.contains(SCHEMA_VERSION_PATTERN),
        "production deployment does not use the tested SCHEMA_VERSION extraction pattern"
    );
    assert!(!workflow.contains("OLDEST_MIGRATABLE_SCHEMA_VERSION"));
    assert!(workflow.contains("if (( actual_schema != required_schema )); then"));
    assert!(workflow.contains("does not exactly match build schema"));
    assert!(!workflow.contains("actual_schema <"));
    assert!(!workflow.contains("actual_schema >"));
    let output = Command::new("sed")
        .args(["-nE", SCHEMA_VERSION_PATTERN])
        .arg(workspace_root().join(SCHEMA_PATH))
        .output()
        .unwrap_or_else(|error| panic!("run sed for SCHEMA_VERSION: {error}"));
    assert!(output.status.success(), "sed failed for SCHEMA_VERSION");
    let value = String::from_utf8(output.stdout).expect("schema version is UTF-8");
    assert!(
        value.trim().parse::<i64>().is_ok(),
        "AUTHORITY_RELEASE_SCHEMA_VERSION did not yield one numeric value: {value:?}"
    );
}

#[test]
fn production_schema_probe_fails_closed() {
    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    let runner = read_workspace_file("deploy/aws/run-postgres-probe.sh");
    let probe = workflow
        .split("# The control store lives in PostgreSQL.")
        .nth(1)
        .and_then(|rest| rest.split("- name: Initialize application state").next())
        .expect("control schema probe block");

    assert!(probe.contains("query_status=$?"));
    assert!(probe.contains("deploy/aws/run-postgres-probe.sh"));
    assert!(probe.contains("SELECT version FROM control_schema_version"));
    assert!(runner.contains("-v ON_ERROR_STOP=1"));
    assert!(runner.contains("logs \"$probe\" --container=psql"));
    assert!(runner.contains("state.terminated.exitCode"));
    assert!(
        !runner
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .any(|line| line.contains("--attach")),
        "the schema probe must not attach to the short-lived container"
    );
    assert!(probe.contains(r#"relation "control_schema_version" does not exist"#));
    assert!(
        !probe.contains("2>/dev/null || true"),
        "database, cluster and scheduling failures must not look like a fresh schema"
    );
    assert!(
        !probe.contains("[[ -z \"$query_output\""),
        "an empty probe response is a failure, not an empty database"
    );
}

#[test]
fn linux_quality_gate_installs_the_postgres_probe_runtime() {
    let quality = read_workspace_file("scripts/quality.sh");
    let linux_gate = read_workspace_file("scripts/linux-gate.sh");

    assert!(quality.contains("exec \"$REPO_ROOT/scripts/linux-gate.sh\""));
    assert!(
        linux_gate.contains("apt-get install -qy --no-install-recommends e2fsprogs jq"),
        "the Linux gate must install jq before deployment probe fixtures execute"
    );
    for field in ["ROOT", "HEAD", "DIRTY", "FINGERPRINT"] {
        assert!(
            quality.contains(&format!(
                "export CATS_SOURCE_PROVENANCE_{field}=\"$SOURCE_PROVENANCE_{field}\""
            )),
            "the Linux gate must export the host's complete source provenance"
        );
    }
    assert!(linux_gate.contains("--ulimit nofile=65536:65536"));
    assert!(linux_gate.contains("env -u GIT_DIR -u GIT_WORK_TREE -u GIT_COMMON_DIR"));
    assert!(linux_gate.contains("GIT_CEILING_DIRECTORIES=\"$(dirname \"$LINUX_CAPTURE_DIR\")\""));
    assert!(linux_gate.contains("git -C \"$LINUX_CAPTURE_DIR\" hash-object --stdin --no-filters"));
    assert!(linux_gate.contains("[[ \"$LINUX_TARGET_NAMESPACE\" =~ ^[0-9a-f]{40}$"));
    assert!(
        !linux_gate.contains("git -C \"$REPO_ROOT\" hash-object --stdin"),
        "target isolation must not reopen host-only worktree Git metadata inside Linux"
    );
    assert!(
        linux_gate.contains("LINUX_TARGET_DIRECTORY=\"/target/worktrees/$LINUX_TARGET_NAMESPACE\"")
    );
    assert!(
        linux_gate.contains("-e CATS_LINUX_TARGET_DIRECTORY=\"$LINUX_TARGET_DIRECTORY\""),
        "the Linux gate must pass its worktree-isolated target root into the container"
    );
    assert_eq!(
        linux_gate
            .matches("--target-dir \"$CATS_LINUX_TARGET_DIRECTORY\"")
            .count(),
        5,
        "check, build, Clippy, tests and rustdoc must share the isolated target root"
    );
    assert!(!linux_gate.contains("--target-dir /target"));
}

#[test]
fn linux_quality_gate_uses_capability_owned_cancellation_safe_cleanup() {
    let quality = read_workspace_file("scripts/quality.sh");
    let linux_gate = read_workspace_file("scripts/linux-gate.sh");
    let (workspace_gate, _) = linux_gate
        .split_once("# ProvisionRootImage restart inventory must query a real system manager.")
        .expect("focused systemd gate boundary");

    assert!(quality.contains("run_linux() {"));
    assert!(quality.contains("exec \"$REPO_ROOT/scripts/linux-gate.sh\""));
    assert!(!quality.contains("run_linux() ("));
    assert!(
        !workspace_gate.lines().any(|line| {
            let line = line.trim_start();
            !line.starts_with('#') && line.contains("--privileged")
        }),
        "the workspace-wide Linux gate must stay unprivileged"
    );
    assert!(linux_gate.contains("create --name \"$LINUX_WORKSPACE_GATE\""));
    assert!(linux_gate.contains("start --attach \"$LINUX_WORKSPACE_GATE\""));
    for (intent, command) in [
        (
            "LINUX_NETWORK_INTENDED=true",
            "network create --label \"$LINUX_OWNER_LABEL\" \"$LINUX_NETWORK\"",
        ),
        ("LINUX_PG_INTENDED=true", "create --name \"$LINUX_PG\""),
        (
            "LINUX_WORKSPACE_INTENDED=true",
            "create --name \"$LINUX_WORKSPACE_GATE\"",
        ),
        (
            "LINUX_SYSTEMD_INTENDED=true",
            "create --name \"$LINUX_SYSTEMD_GATE\"",
        ),
    ] {
        let intent_position = linux_gate
            .find(intent)
            .unwrap_or_else(|| panic!("Linux cleanup lost intent {intent:?}"));
        let command_position = linux_gate
            .find(command)
            .unwrap_or_else(|| panic!("Linux gate lost Docker call {command:?}"));
        assert!(
            intent_position < command_position,
            "cleanup intent {intent:?} must precede response-loss-prone Docker call {command:?}"
        );
    }
    for required in [
        "LINUX_RUN_TOKEN=\"$(LC_ALL=C od -An -N16 -tx1 /dev/urandom",
        "LINUX_OWNER_KEY=\"io.cats.quality.linux.owner\"",
        "--label \"$LINUX_OWNER_LABEL\"",
        "LINUX_ACTIVE_DOCKER_PID=$!",
        "LINUX_ACTIVE_DOCKER_KIND=\"$kind\"",
        "docker_create_cli",
        "settle_active_create",
        "reconcile_pending_create",
        "LINUX_CREATE_PENDING=true",
        "LINUX_CREATE_ARGUMENTS=(\"$@\")",
        "trap '' INT TERM",
        "set -m",
        "LINUX_CREATE_SETTLEMENT_UNKNOWN=true",
        "Container create\n  # and start are separate",
        "probe_owned_container",
        "probe_owned_network",
        "remove_owned_container \"$LINUX_SYSTEMD_INTENDED\" \"$LINUX_SYSTEMD_GATE\" true",
        "remove_owned_container \"$LINUX_WORKSPACE_INTENDED\" \"$LINUX_WORKSPACE_GATE\" false",
        "remove_owned_container \"$LINUX_PG_INTENDED\" \"$LINUX_PG\" false",
        "remove_owned_network \"$LINUX_NETWORK_INTENDED\" \"$LINUX_NETWORK\"",
        "all_intended_resources_absent",
        "LINUX_CLEANUP_DEADLINE=$((SECONDS + LINUX_CLEANUP_BUDGET_SECONDS))",
        "trap linux_gate_on_exit EXIT",
        "trap 'linux_gate_signal 130' INT",
        "trap 'linux_gate_signal 143' TERM",
    ] {
        assert!(
            linux_gate.contains(required),
            "the capability-owned cancellation-safe Linux cleanup lost {required:?}"
        );
    }
    assert!(
        !linux_gate.contains("absent_rounds"),
        "elapsed absence is not proof that an interrupted create request settled"
    );
}

#[test]
fn linux_quality_gate_pins_one_private_systemd_e2e_to_an_immutable_image() {
    let linux_gate = read_workspace_file("scripts/linux-gate.sh");
    let (_, systemd_gate) = linux_gate
        .split_once("# ProvisionRootImage restart inventory must query a real system manager.")
        .expect("focused systemd gate boundary");

    for required in [
        "LINUX_SYSTEMD_IIDFILE=\"$LINUX_CAPTURE_DIR/systemd-image.iid\"",
        "--iidfile \"$LINUX_SYSTEMD_IIDFILE\"",
        "cmp -s \"$LINUX_SYSTEMD_IIDFILE\" \"$iidfile_expected\"",
        "cmp -s \"$LINUX_SYSTEMD_IIDFILE\" \"$iidfile_expected_lf\"",
        "CATS_SOURCE_PROVENANCE_FINGERPRINT=$CATS_SOURCE_PROVENANCE_FINGERPRINT",
        "^sha256:[0-9a-f]{64}$",
        "image inspect",
        "LINUX_SYSTEMD_IMAGE_ID|$CATS_SOURCE_PROVENANCE_FINGERPRINT",
        "\"$LINUX_SYSTEMD_IMAGE_ID\" /lib/systemd/systemd",
        "--privileged",
        "--cgroupns=private",
        "--cgroup-parent system.slice",
        "--tmpfs /run",
        "--tmpfs /run/lock",
        "-e container=docker",
        "target=/work,readonly",
        "cat /proc/1/comm",
        "cat /proc/1/cgroup",
        "0::/init.scope",
        "systemctl is-system-running --quiet",
        "-- --ignored --exact --list",
        "listed_test_count=$((listed_test_count + 1))",
        "listed_test_count\" -ne 1",
        "listed_test_mismatch\" == true",
        "focused Linux Runtime E2E test inventory was not the exact known positive",
        "timeout --signal=TERM --kill-after=30s 20m",
        "install -D -m 0755 \"$source_binary\" \"$target_binary\"",
        "cmp -s \"$source_binary\" \"$target_binary\"",
    ] {
        assert!(
            systemd_gate.contains(required) || linux_gate.contains(required),
            "the focused real-systemd E2E lost boundary {required:?}"
        );
    }
    assert!(
        !systemd_gate.contains("--tag"),
        "the focused systemd container must not be created through a mutable tag"
    );
    assert!(
        !systemd_gate.contains("wc -l <\"$LINUX_SYSTEMD_IIDFILE\""),
        "BuildKit may write its exact iidfile receipt without a terminal newline"
    );
    assert!(
        !linux_gate.contains("image rm"),
        "run cleanup must not delete content-addressed image cache shared by concurrent gates"
    );
    assert_eq!(
        linux_gate.matches("--privileged").count(),
        1,
        "privilege must be confined to the one focused systemd container"
    );
    for forbidden in ["--cgroupns=host", "source=/sys/fs/cgroup", "--network host"] {
        assert!(
            !systemd_gate.contains(forbidden),
            "the focused systemd E2E escaped its private boundary {forbidden:?}"
        );
    }
    let focused_command = systemd_gate
        .replace("\\\n", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        focused_command.contains(
            "exec \"$LINUX_SYSTEMD_GATE\" timeout --signal=TERM --kill-after=30s 20m cargo test -p cats-node-agent --lib --locked --target-dir \"$LINUX_TARGET_DIRECTORY\" runtime_cutover::cross_component_e2e::postgres_control_and_production_cutover_reconcile_one_created_cat_across_restart -- --ignored --exact --nocapture"
        ),
        "the privileged gate must run only the exact ignored Node E2E"
    );
    assert!(
        !systemd_gate.contains("--workspace"),
        "the privileged focused block must never run workspace-wide Cargo"
    );

    let image = read_workspace_file("scripts/linux-systemd.Dockerfile");
    for required in [
        "FROM rust:1.97.1-bookworm",
        "ARG CATS_SOURCE_PROVENANCE_FINGERPRINT",
        "LABEL io.cats.quality.source-fingerprint=",
        "e2fsprogs",
        "iproute2",
        "jq",
        "systemd",
        "rm -rf /var/lib/apt/lists/*",
        "STOPSIGNAL SIGRTMIN+3",
        "CMD [\"/lib/systemd/systemd\"]",
    ] {
        assert!(
            image.contains(required),
            "the focused systemd image lost {required:?}"
        );
    }
    assert!(
        !image.lines().any(|line| {
            let instruction = line.trim_start().to_ascii_uppercase();
            instruction.starts_with("COPY ") || instruction.starts_with("ADD ")
        }),
        "the focused PID-1 image must not embed a mutable source snapshot"
    );
}

#[cfg(unix)]
const LINUX_GATE_TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[cfg(unix)]
fn write_executable(path: &Path, source: &str) {
    std::fs::write(path, source)
        .unwrap_or_else(|error| panic!("write executable {}: {error}", path.display()));
    let mut permissions = std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("read executable metadata {}: {error}", path.display()))
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)
        .unwrap_or_else(|error| panic!("make {} executable: {error}", path.display()));
}

#[cfg(unix)]
fn install_linux_gate_fake_cli(bin: &Path) {
    std::fs::create_dir_all(bin).expect("create Linux gate fake bin");
    write_executable(
        &bin.join("od"),
        &format!("#!/bin/sh\nprintf ' {LINUX_GATE_TEST_TOKEN}\\n'\n"),
    );
    write_executable(
        &bin.join("docker"),
        r#"#!/usr/bin/env bash
set -euo pipefail

state=${CATS_FAKE_DOCKER_STATE:?}
mode=${CATS_FAKE_DOCKER_MODE:?}
trace="$state/trace"
mkdir -p "$state"
printf '%s\n' "$*" >>"$trace"

object_path() {
  printf '%s/%s.%s\n' "$state" "$1" "$2"
}

object_by_id() {
  local kind="$1"
  local wanted="$2"
  local candidate
  local id
  shopt -s nullglob
  for candidate in "$state/$kind."*; do
    IFS='|' read -r id _ <"$candidate"
    if [[ "$id" == "$wanted" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

label_value() {
  local previous=""
  local argument
  for argument in "$@"; do
    if [[ "$previous" == --label ]]; then
      printf '%s\n' "${argument#*=}"
      return 0
    fi
    previous="$argument"
  done
  return 1
}

named_value() {
  local previous=""
  local argument
  for argument in "$@"; do
    if [[ "$previous" == --name ]]; then
      printf '%s\n' "$argument"
      return 0
    fi
    previous="$argument"
  done
  return 1
}

argument_after() {
  local wanted="$1"
  local previous=""
  local argument
  shift
  for argument in "$@"; do
    if [[ "$previous" == "$wanted" ]]; then
      printf '%s\n' "$argument"
      return 0
    fi
    previous="$argument"
  done
  return 1
}

case "${1:-} ${2:-}" in
  "build "*)
    iidfile="$(argument_after --iidfile "$@")"
    provenance="$(argument_after --build-arg "$@")"
    provenance="${provenance#CATS_SOURCE_PROVENANCE_FINGERPRINT=}"
    image_id="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    case "$mode" in
      iidfile-one-lf) printf '%s\n' "$image_id" >"$iidfile" ;;
      iidfile-two-lf) printf '%s\n\n' "$image_id" >"$iidfile" ;;
      iidfile-nul) printf '%s\0' "$image_id" >"$iidfile" ;;
      iidfile-second-line) printf '%s\n%s\n' "$image_id" "$image_id" >"$iidfile" ;;
      iidfile-garbage) printf '%s!' "$image_id" >"$iidfile" ;;
      *) printf '%s' "$image_id" >"$iidfile" ;;
    esac
    printf '%s|%s\n' "$image_id" "$provenance" >"$state/systemd-image"
    ;;
  "image inspect")
    id="${!#}"
    IFS='|' read -r stored_id provenance <"$state/systemd-image"
    [[ "$id" == "$stored_id" ]] || exit 64
    printf '%s|%s\n' "$stored_id" "$provenance"
    ;;
  "network create")
    name="${!#}"
    owner="$(label_value "$@")"
    path="$(object_path network "$name")"
    [[ ! -e "$path" ]] || exit 125
    printf 'owned-network-id|%s\n' "$owner" >"$path"
    printf 'owned-network-id\n'
    ;;
  "network ls")
    name=""
    for argument in "$@"; do
      if [[ "$argument" == name=^*'$' ]]; then
        name="${argument#name=^}"
        name="${name%\$}"
      fi
    done
    path="$(object_path network "$name")"
    if [[ -e "$path" ]]; then
      IFS='|' read -r id _ <"$path"
      printf '%s\n' "$id"
    fi
    ;;
  "network inspect")
    id="${!#}"
    path="$(object_by_id network "$id")"
    name="${path#"$state/network."}"
    IFS='|' read -r stored_id owner <"$path"
    printf '%s|%s|%s\n' "$stored_id" "$name" "$owner"
    ;;
  "network rm")
    id="${!#}"
    if [[ -e "$state/workspace-network-active" && ! -e "$state/late-workspace-removed" ]]; then
      printf 'network has active endpoints\n' >&2
      exit 1
    fi
    path="$(object_by_id network "$id")"
    rm -f -- "$path"
    ;;
  "container ls")
    if [[ "$mode" == cleanup-hang && -e "$state/workspace-network-active" ]]; then
      : >"$state/cleanup-hang-entered"
      trap '' TERM
      while :; do sleep 0.2; done
    fi
    name=""
    for argument in "$@"; do
      if [[ "$argument" == name=^/*'$' ]]; then
        name="${argument#name=^/}"
        name="${name%\$}"
      fi
    done
    path="$(object_path container "$name")"
    if [[ -e "$path" ]]; then
      IFS='|' read -r id _ <"$path"
      printf '%s\n' "$id"
    fi
    ;;
  "container inspect")
    id="${!#}"
    path="$(object_by_id container "$id")"
    name="${path#"$state/container."}"
    IFS='|' read -r stored_id owner <"$path"
    printf '%s|/%s|%s\n' "$stored_id" "$name" "$owner"
    ;;
  "stop "*)
    ;;
  "rm -f")
    id="${!#}"
    path="$(object_by_id container "$id")"
    rm -f -- "$path"
    if [[ "$id" == late-workspace-id \
      || "$id" == response-loss-workspace-id \
      || "$id" == owned-cats-linux-workspace-gate-*-id ]]; then
      : >"$state/late-workspace-removed"
    fi
    if [[ "$id" == owned-cats-linux-systemd-gate-*-id ]]; then
      : >"$state/systemd-removed"
    fi
    ;;
  "create "*)
    name="$(named_value "$@")"
    owner="$(label_value "$@")"
    path="$(object_path container "$name")"
    [[ ! -e "$path" ]] || exit 125
    if [[ "$mode" == cleanup-hang && "$name" == cats-linux-workspace-gate-* ]]; then
      printf 'owned-workspace-id|%s\n' "$owner" >"$path"
      : >"$state/workspace-network-active"
      : >"$state/create-settlement-hang-entered"
      trap '' TERM
      while :; do sleep 0.2; done
    fi
    if [[ "$mode" == term-delayed-create && "$name" == cats-linux-workspace-gate-* ]]; then
      : >"$state/workspace-network-active"
      nohup /bin/bash -c '
        sleep 5.2
        state=$1
        name=$2
        owner=$3
        temporary="$state/container.$name.pending"
        printf "late-workspace-id|%s\\n" "$owner" >"$temporary"
        mv -- "$temporary" "$state/container.$name"
        : >"$state/late-marker"
        : >"$state/create-response"
        printf "LATE_CREATE late-workspace-id\\n" >>"$state/trace"
      ' fake-daemon "$state" "$name" "$owner" >/dev/null 2>&1 &
      while [[ ! -e "$state/create-response" ]]; do sleep 0.1; done
      printf 'late-workspace-id\n'
      exit 0
    fi
    if [[ "$mode" == response-loss-late-create && "$name" == cats-linux-workspace-gate-* ]]; then
      count_path="$state/response-loss-create-count"
      count=0
      [[ ! -e "$count_path" ]] || IFS= read -r count <"$count_path"
      count=$((count + 1))
      printf '%s\n' "$count" >"$count_path"
      if [[ "$count" -eq 1 ]]; then
        : >"$state/workspace-network-active"
        nohup /bin/bash -c '
          trap "" INT TERM
          sleep 5.2
          state=$1
          name=$2
          owner=$3
          temporary="$state/container.$name.pending"
          printf "response-loss-workspace-id|%s\\n" "$owner" >"$temporary"
          mv -- "$temporary" "$state/container.$name"
          : >"$state/response-loss-late-marker"
          printf "RESPONSE_LOSS_LATE_CREATE response-loss-workspace-id\\n" >>"$state/trace"
        ' fake-daemon "$state" "$name" "$owner" >/dev/null 2>&1 &
        : >"$state/first-response-lost"
        exit 125
      fi
      : >"$state/idempotent-retry-entered"
      while [[ ! -e "$path" ]]; do sleep 0.1; done
      : >"$state/idempotent-name-reserved"
      exit 125
    fi
    printf 'owned-%s-id|%s\n' "$name" "$owner" >"$path"
    printf 'owned-%s-id\n' "$name"
    ;;
  "start "*)
    name="${!#}"
    if [[ "$mode" == term-start && "$name" == cats-linux-workspace-gate-* ]]; then
      : >"$state/workspace-network-active"
      : >"$state/start-entered"
      trap '' TERM
      while :; do sleep 0.2; done
    fi
    ;;
  "exec "*)
    case "$*" in
      *" cat /proc/1/comm") printf 'systemd\n' ;;
      *" cat /proc/1/cgroup") printf '0::/init.scope\n' ;;
      *" systemctl is-system-running --quiet") ;;
      *" sh -ceu "*) : >"$state/blockd-installed" ;;
      *" cargo test "*" -- --ignored --exact --list")
        if [[ "$mode" != zero-systemd-test ]]; then
          printf '%s\n' \
            'runtime_cutover::cross_component_e2e::postgres_control_and_production_cutover_reconcile_one_created_cat_across_restart: test'
        fi
        ;;
      *" timeout --signal=TERM --kill-after=30s 20m cargo test "*)
        : >"$state/focused-systemd-test-ran"
        ;;
      *)
        printf 'unexpected fake Docker exec: %s\n' "$*" >&2
        exit 64
        ;;
    esac
    ;;
  *)
    printf 'unexpected fake Docker command: %s\n' "$*" >&2
    exit 64
    ;;
esac
"#,
    );
}

#[cfg(unix)]
fn linux_gate_command(fake_bin: &Path, state: &Path, mode: &str) -> Command {
    let linked_worktree = state
        .parent()
        .expect("Linux gate fixture parent")
        .join("linked-worktree");
    let scripts = linked_worktree.join("scripts");
    std::fs::create_dir_all(&scripts).expect("create linked-worktree scripts fixture");
    for name in ["quality.sh", "linux-gate.sh"] {
        let destination = scripts.join(name);
        std::fs::copy(workspace_root().join("scripts").join(name), &destination)
            .unwrap_or_else(|error| panic!("copy {name} into linked-worktree fixture: {error}"));
        let mut permissions = std::fs::metadata(&destination)
            .unwrap_or_else(|error| panic!("read {name} fixture metadata: {error}"))
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&destination, permissions)
            .unwrap_or_else(|error| panic!("make {name} fixture executable: {error}"));
    }
    std::fs::write(
        linked_worktree.join(".git"),
        format!(
            "gitdir: {}\n",
            linked_worktree.join("unmounted-host-gitdir").display()
        ),
    )
    .expect("write broken linked-worktree Git indirection");

    let mut command = Command::new(scripts.join("quality.sh"));
    command
        .arg("linux")
        // Exercise the macOS-supported system Bash (3.2) instead of allowing
        // a Homebrew Bash earlier in the developer's inherited PATH to mask
        // an incompatible gate construct.
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", fake_bin.display()),
        )
        .env("CATS_FAKE_DOCKER_STATE", state)
        .env("CATS_FAKE_DOCKER_MODE", mode)
        .env("CATS_SOURCE_PROVENANCE_ROOT", &linked_worktree)
        .env("CATS_SOURCE_PROVENANCE_HEAD", "a".repeat(40))
        .env("CATS_SOURCE_PROVENANCE_DIRTY", "false")
        .env("CATS_SOURCE_PROVENANCE_FINGERPRINT", "b".repeat(40));
    command
}

#[cfg(unix)]
#[test]
fn linux_quality_gate_preserves_same_name_foreign_resources_after_create_collision() {
    for (kind, name, id) in [
        (
            "network",
            format!("cats-linux-net-{LINUX_GATE_TEST_TOKEN}"),
            "foreign-network-id",
        ),
        (
            "container",
            format!("cats-linux-pg-{LINUX_GATE_TEST_TOKEN}"),
            "foreign-container-id",
        ),
        (
            "container",
            format!("cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN}"),
            "foreign-systemd-id",
        ),
    ] {
        let fixture = tempfile::tempdir().expect("Linux gate collision fixture");
        let fake_bin = fixture.path().join("bin");
        let state = fixture.path().join("state");
        std::fs::create_dir_all(&state).expect("create fake Docker state");
        install_linux_gate_fake_cli(&fake_bin);
        let foreign = state.join(format!("{kind}.{name}"));
        let original = format!("{id}|foreign-owner\n");
        std::fs::write(&foreign, &original).expect("preseed foreign Docker resource");

        let output = linux_gate_command(&fake_bin, &state, "collision")
            .output()
            .expect("run Linux gate collision regression");
        assert!(!output.status.success(), "foreign {kind} collision passed");
        assert_eq!(
            std::fs::read_to_string(&foreign).expect("foreign resource survived"),
            original,
            "the Linux gate mutated a same-name foreign {kind}"
        );
        let trace = std::fs::read_to_string(state.join("trace")).expect("fake Docker trace");
        assert!(
            !trace.lines().any(|line| {
                line == format!("stop --time 20 {id}")
                    || line == format!("rm -f {id}")
                    || line == format!("network rm {id}")
            }),
            "the Linux gate attempted to remove foreign immutable ID {id}:\n{trace}"
        );
        for owned_resource in [
            format!("network.cats-linux-net-{LINUX_GATE_TEST_TOKEN}"),
            format!("container.cats-linux-pg-{LINUX_GATE_TEST_TOKEN}"),
            format!("container.cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}"),
            format!("container.cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN}"),
        ] {
            if state.join(&owned_resource) != foreign {
                assert!(
                    !state.join(&owned_resource).exists(),
                    "foreign {kind} collision blocked exact cleanup of {owned_resource}:\n{trace}"
                );
            }
        }
        if id == "foreign-systemd-id" {
            for exact_cleanup in [
                format!("rm -f owned-cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}-id"),
                format!("rm -f owned-cats-linux-pg-{LINUX_GATE_TEST_TOKEN}-id"),
                "network rm owned-network-id".to_owned(),
            ] {
                assert!(
                    trace.contains(&exact_cleanup),
                    "foreign systemd collision skipped cleanup {exact_cleanup:?}:\n{trace}"
                );
            }
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("refusing to remove foreign Linux gate"),
            "foreign owner mismatch was not diagnosed:\n{stderr}"
        );
    }
}

#[cfg(unix)]
#[test]
fn linux_quality_gate_process_group_term_preserves_create_receipt_before_exact_cleanup() {
    let fixture = tempfile::tempdir().expect("Linux gate TERM fixture");
    let fake_bin = fixture.path().join("bin");
    let state = fixture.path().join("state");
    std::fs::create_dir_all(&state).expect("create fake Docker state");
    install_linux_gate_fake_cli(&fake_bin);
    let stdout_path = fixture.path().join("stdout");
    let stderr_path = fixture.path().join("stderr");
    let stdout = std::fs::File::create(&stdout_path).expect("create stdout capture");
    let stderr = std::fs::File::create(&stderr_path).expect("create stderr capture");
    let mut command = linux_gate_command(&fake_bin, &state, "term-delayed-create");
    command
        .process_group(0)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let mut child = command
        .spawn()
        .expect("start isolated Linux quality-gate process group");

    let workspace_started = Instant::now();
    while !state.join("workspace-network-active").exists() {
        assert!(
            workspace_started.elapsed() < Duration::from_secs(8),
            "fake Docker never entered the foreground workspace run"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let signal_at = Instant::now();
    let signal = Command::new("kill")
        .args(["-TERM", "--", &format!("-{}", child.id())])
        .status()
        .expect("signal Linux quality-gate process group");
    assert!(
        signal.success(),
        "could not TERM Linux quality-gate process group"
    );

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut removed_at = None;
    let status = loop {
        if removed_at.is_none() && state.join("late-workspace-removed").exists() {
            removed_at = Some(Instant::now());
        }
        if let Some(status) = child.try_wait().expect("poll Linux quality gate") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out Linux quality gate");
            child.wait().expect("reap timed-out Linux quality gate");
            panic!("TERM cleanup exceeded its 15-second bound");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(143));
    let removed_at = removed_at.expect("late workspace immutable-ID removal marker");
    assert!(
        removed_at.duration_since(signal_at) >= Duration::from_millis(4_800),
        "cleanup acted before the daemon returned the deliberately delayed create receipt"
    );
    assert!(
        state.join("late-marker").exists(),
        "test never observed the daemon-side create after the signal"
    );

    for resource in [
        format!("network.cats-linux-net-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-pg-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}"),
    ] {
        assert!(
            !state.join(&resource).exists(),
            "intended resource remained after TERM cleanup: {resource}"
        );
    }
    let trace = std::fs::read_to_string(state.join("trace")).expect("fake Docker trace");
    let late_create = trace
        .find("LATE_CREATE late-workspace-id")
        .expect("late daemon-side create trace");
    let immutable_remove = trace
        .find("rm -f late-workspace-id")
        .expect("immutable-ID cleanup trace");
    assert!(
        late_create < immutable_remove,
        "settled late resource was not removed by immutable ID:\n{trace}"
    );
    assert!(
        trace.contains("network rm owned-network-id"),
        "the previously active network did not converge to removal:\n{trace}"
    );
}

#[cfg(unix)]
#[test]
fn linux_quality_gate_retries_response_loss_until_exact_owned_create_is_observable() {
    let fixture = tempfile::tempdir().expect("Linux gate response-loss fixture");
    let fake_bin = fixture.path().join("bin");
    let state = fixture.path().join("state");
    std::fs::create_dir_all(&state).expect("create fake Docker state");
    install_linux_gate_fake_cli(&fake_bin);

    let started_at = Instant::now();
    let output = linux_gate_command(&fake_bin, &state, "response-loss-late-create")
        .output()
        .expect("run Linux quality gate response-loss regression");
    assert!(
        output.status.success(),
        "response-loss reconciliation failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started_at.elapsed() >= Duration::from_millis(4_800),
        "response loss was blessed before the delayed daemon create became observable"
    );
    for marker in [
        "first-response-lost",
        "idempotent-retry-entered",
        "idempotent-name-reserved",
        "response-loss-late-marker",
        "late-workspace-removed",
        "blockd-installed",
        "focused-systemd-test-ran",
        "systemd-removed",
    ] {
        assert!(
            state.join(marker).exists(),
            "response-loss regression did not exercise {marker}"
        );
    }
    for resource in [
        format!("network.cats-linux-net-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-pg-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN}"),
    ] {
        assert!(
            !state.join(&resource).exists(),
            "intended resource remained after response-loss settlement: {resource}"
        );
    }

    let trace = std::fs::read_to_string(state.join("trace")).expect("fake Docker trace");
    let create_call = format!("create --name cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}");
    assert_eq!(
        trace.matches(&create_call).count(),
        2,
        "the ambiguous first response was not closed by one same-name retry:\n{trace}"
    );
    let late_create = trace
        .find("RESPONSE_LOSS_LATE_CREATE response-loss-workspace-id")
        .expect("late daemon create trace");
    let immutable_remove = trace
        .find("rm -f response-loss-workspace-id")
        .expect("response-loss immutable-ID removal trace");
    assert!(
        late_create < immutable_remove,
        "cleanup raced the response-loss daemon create:\n{trace}"
    );
    let immutable_image = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let systemd_create = trace
        .lines()
        .find(|line| {
            line.starts_with(&format!(
                "create --name cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN} "
            ))
        })
        .expect("focused systemd immutable-image create trace");
    assert!(
        systemd_create.ends_with(&format!("{immutable_image} /lib/systemd/systemd")),
        "focused systemd create did not consume the iidfile image ID:\n{trace}"
    );
    let systemd_id = format!("owned-cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN}-id");
    assert!(
        trace.contains(&format!("stop --time 20 {systemd_id}"))
            && trace.contains(&format!("rm -f {systemd_id}")),
        "focused systemd container was not gracefully and exactly cleaned:\n{trace}"
    );
}

#[cfg(unix)]
#[test]
fn linux_quality_gate_rejects_an_empty_focused_systemd_test_filter() {
    let fixture = tempfile::tempdir().expect("Linux gate empty focused-test fixture");
    let fake_bin = fixture.path().join("bin");
    let state = fixture.path().join("state");
    std::fs::create_dir_all(&state).expect("create fake Docker state");
    install_linux_gate_fake_cli(&fake_bin);

    let output = linux_gate_command(&fake_bin, &state, "zero-systemd-test")
        .output()
        .expect("run Linux gate empty focused-test regression");
    assert!(
        !output.status.success(),
        "an empty exact Rust test filter incorrectly passed the Linux gate"
    );
    assert!(
        !state.join("focused-systemd-test-ran").exists(),
        "the real focused command ran after its known-positive probe returned zero tests"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr
            .contains("focused Linux Runtime E2E test inventory was not the exact known positive"),
        "the empty exact test filter was not diagnosed:\n{stderr}"
    );
    for resource in [
        format!("network.cats-linux-net-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-pg-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN}"),
    ] {
        assert!(
            !state.join(&resource).exists(),
            "intended resource remained after empty test-inventory failure: {resource}"
        );
    }
    let trace = std::fs::read_to_string(state.join("trace")).expect("fake Docker trace");
    let systemd_id = format!("owned-cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN}-id");
    assert!(
        trace.contains(&format!("stop --time 20 {systemd_id}"))
            && trace.contains(&format!("rm -f {systemd_id}")),
        "empty test-inventory failure did not clean the focused container exactly:\n{trace}"
    );
}

#[cfg(unix)]
#[test]
fn linux_quality_gate_accepts_exact_iidfile_frames_and_rejects_trailing_data() {
    for mode in ["iidfile-no-lf", "iidfile-one-lf"] {
        let fixture = tempfile::tempdir().expect("Linux gate valid iidfile fixture");
        let fake_bin = fixture.path().join("bin");
        let state = fixture.path().join("state");
        std::fs::create_dir_all(&state).expect("create fake Docker state");
        install_linux_gate_fake_cli(&fake_bin);

        let output = linux_gate_command(&fake_bin, &state, mode)
            .output()
            .unwrap_or_else(|error| panic!("run Linux gate {mode} regression: {error}"));
        assert!(
            output.status.success(),
            "valid iidfile mode {mode} was not accepted:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            state.join("focused-systemd-test-ran").exists(),
            "valid iidfile mode {mode} did not reach the exact focused systemd test"
        );
        assert!(
            state.join("systemd-removed").exists(),
            "valid iidfile mode {mode} did not converge through exact systemd cleanup"
        );
    }

    for mode in [
        "iidfile-two-lf",
        "iidfile-nul",
        "iidfile-second-line",
        "iidfile-garbage",
    ] {
        let fixture = tempfile::tempdir().expect("Linux gate malformed iidfile fixture");
        let fake_bin = fixture.path().join("bin");
        let state = fixture.path().join("state");
        std::fs::create_dir_all(&state).expect("create fake Docker state");
        install_linux_gate_fake_cli(&fake_bin);

        let output = linux_gate_command(&fake_bin, &state, mode)
            .output()
            .unwrap_or_else(|error| panic!("run Linux gate {mode} regression: {error}"));
        assert!(
            !output.status.success(),
            "malformed iidfile mode {mode} incorrectly passed"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("focused Linux Runtime E2E received an invalid Docker image receipt"),
            "malformed iidfile mode {mode} was not diagnosed:\n{stderr}"
        );
        let trace = std::fs::read_to_string(state.join("trace")).expect("fake Docker trace");
        assert!(
            trace
                .lines()
                .any(|line| line.starts_with("build --platform ")),
            "malformed iidfile mode {mode} did not reach the image receipt boundary:\n{trace}"
        );
        assert!(
            !trace.lines().any(|line| line.starts_with("image inspect ")),
            "malformed iidfile mode {mode} reached image inspection:\n{trace}"
        );
        assert!(
            !trace.lines().any(|line| {
                line.starts_with(&format!(
                    "create --name cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN} "
                ))
            }),
            "malformed iidfile mode {mode} created the privileged systemd container:\n{trace}"
        );
        for resource in [
            format!("network.cats-linux-net-{LINUX_GATE_TEST_TOKEN}"),
            format!("container.cats-linux-pg-{LINUX_GATE_TEST_TOKEN}"),
            format!("container.cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}"),
            format!("container.cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN}"),
        ] {
            assert!(
                !state.join(&resource).exists(),
                "malformed iidfile mode {mode} left owned resource {resource}:\n{trace}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn linux_quality_gate_term_interrupts_start_after_create_receipt_and_cleans_exact_id() {
    let fixture = tempfile::tempdir().expect("Linux gate start TERM fixture");
    let fake_bin = fixture.path().join("bin");
    let state = fixture.path().join("state");
    std::fs::create_dir_all(&state).expect("create fake Docker state");
    install_linux_gate_fake_cli(&fake_bin);
    let mut child = linux_gate_command(&fake_bin, &state, "term-start")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start top-level Linux quality gate");

    let start_deadline = Instant::now() + Duration::from_secs(8);
    while !state.join("start-entered").exists() {
        if Instant::now() >= start_deadline {
            child.kill().expect("kill Linux gate missing start marker");
            child.wait().expect("reap Linux gate missing start marker");
            panic!("fake Docker never entered workspace start --attach");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let signal_at = Instant::now();
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("signal top-level quality gate")
            .success(),
        "could not TERM top-level quality gate"
    );
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll Linux quality gate") {
            break status;
        }
        if signal_at.elapsed() >= Duration::from_secs(8) {
            child.kill().expect("kill timed-out Linux quality gate");
            child.wait().expect("reap timed-out Linux quality gate");
            panic!("start cancellation and exact cleanup exceeded eight seconds");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(143));
    assert!(
        signal_at.elapsed() < Duration::from_secs(6),
        "settled create incorrectly made start wait for create-style settlement"
    );
    for resource in [
        format!("network.cats-linux-net-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-pg-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}"),
    ] {
        assert!(
            !state.join(&resource).exists(),
            "intended resource remained after start cancellation: {resource}"
        );
    }
    let trace = std::fs::read_to_string(state.join("trace")).expect("fake Docker trace");
    let create = trace
        .find(&format!(
            "create --name cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}"
        ))
        .expect("workspace create trace");
    let start = trace
        .find(&format!(
            "start --attach cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}"
        ))
        .expect("workspace start trace");
    let remove = trace
        .find(&format!(
            "rm -f owned-cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}-id"
        ))
        .expect("workspace immutable-ID removal trace");
    assert!(
        create < start && start < remove,
        "workspace create/start/immutable-ID cleanup order was not causal:\n{trace}"
    );
}

#[cfg(unix)]
#[test]
fn linux_quality_gate_cleanup_has_one_hard_deadline_when_docker_cli_hangs() {
    let fixture = tempfile::tempdir().expect("Linux gate cleanup deadline fixture");
    let fake_bin = fixture.path().join("bin");
    let state = fixture.path().join("state");
    std::fs::create_dir_all(&state).expect("create fake Docker state");
    install_linux_gate_fake_cli(&fake_bin);
    let stdout_path = fixture.path().join("stdout");
    let stderr_path = fixture.path().join("stderr");
    let stdout = std::fs::File::create(&stdout_path).expect("create stdout capture");
    let stderr = std::fs::File::create(&stderr_path).expect("create stderr capture");
    let mut child = linux_gate_command(&fake_bin, &state, "cleanup-hang")
        .env("CATS_LINUX_CLEANUP_BUDGET_SECONDS", "5")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("start top-level Linux quality gate");

    let workspace_started = Instant::now();
    while !state.join("workspace-network-active").exists() {
        assert!(
            workspace_started.elapsed() < Duration::from_secs(8),
            "fake Docker never entered the foreground workspace run"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let signal_at = Instant::now();
    let signal = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("signal top-level quality gate");
    assert!(signal.success(), "could not TERM top-level quality gate");

    let deadline = signal_at + Duration::from_secs(9);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll Linux quality gate") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out Linux quality gate");
            child.wait().expect("reap timed-out Linux quality gate");
            panic!("hung cleanup exceeded its nine-second test deadline");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let elapsed = signal_at.elapsed();
    assert_eq!(status.code(), Some(143));
    assert!(
        elapsed < Duration::from_secs(8),
        "five-second shared cleanup budget took {elapsed:?} after TERM"
    );
    assert!(
        state.join("create-settlement-hang-entered").exists(),
        "test never exercised a create receipt that remained unknown at the shared deadline"
    );
    let stderr = std::fs::read_to_string(&stderr_path).expect("read cleanup stderr");
    assert!(
        stderr.contains("Docker create request did not settle before the Linux cleanup deadline"),
        "hung daemon create did not hit the shared settlement deadline:\n{stderr}"
    );
    assert!(
        stderr.contains("Linux gate has an unsettled Docker create result"),
        "an unknown daemon create result was incorrectly treated as absence:\n{stderr}"
    );
    assert!(
        stderr.contains("Linux gate resources did not converge to exact absence"),
        "cleanup timeout was not reported as non-convergence:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn quality_gate_declares_native_linux_test_resources() {
    let root = workspace_root();
    let fixture = tempfile::tempdir().expect("quality process-limit fixture");
    let fake_cargo = fixture.path().join("cargo");
    let capture = fixture.path().join("capture");
    std::fs::write(
        &fake_cargo,
        r#"#!/usr/bin/env bash
set -euo pipefail
printf 'soft=%s\n' "$(ulimit -Sn)" > "$CATS_QUALITY_CAPTURE"
printf 'hard=%s\n' "$(ulimit -Hn)" >> "$CATS_QUALITY_CAPTURE"
printf 'path=%s\n' "$PATH" >> "$CATS_QUALITY_CAPTURE"
printf 'args=%s\n' "$*" >> "$CATS_QUALITY_CAPTURE"
"#,
    )
    .expect("write fake cargo");
    let mut permissions = std::fs::metadata(&fake_cargo)
        .expect("fake cargo metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_cargo, permissions).expect("make fake cargo executable");
    for (name, body) in [
        ("uname", "#!/bin/sh\nprintf 'Linux\\n'\n"),
        ("mkfs.ext4", "#!/bin/sh\nexit 0\n"),
        ("debugfs", "#!/bin/sh\nexit 0\n"),
        ("e2fsck", "#!/bin/sh\nexit 0\n"),
    ] {
        let path = fixture.path().join(name);
        std::fs::write(&path, body).expect("write native-tool fixture");
        let mut permissions = std::fs::metadata(&path)
            .expect("native-tool fixture metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("make native-tool fixture executable");
    }

    let inherited_path = std::env::var("PATH").expect("PATH");
    let output = Command::new("bash")
        .arg("-c")
        .arg("ulimit -Sn 1024\nexec \"$QUALITY_SCRIPT\" test")
        .env("QUALITY_SCRIPT", root.join("scripts/quality.sh"))
        .env("CATS_QUALITY_CAPTURE", &capture)
        .env("CATS_TEST_POSTGRES_URL", "postgres://unused")
        .env(
            "PATH",
            format!("{}:{inherited_path}", fixture.path().display()),
        )
        .output()
        .expect("run quality test process-limit probe");
    assert!(
        output.status.success(),
        "quality probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let captured = std::fs::read_to_string(capture).expect("read process-limit capture");
    let soft = captured
        .lines()
        .find_map(|line| line.strip_prefix("soft="))
        .expect("soft nofile capture");
    let hard = captured
        .lines()
        .find_map(|line| line.strip_prefix("hard="))
        .expect("hard nofile capture");
    assert_eq!(soft, hard);
    assert_ne!(soft, "1024");
    let path = captured
        .lines()
        .find_map(|line| line.strip_prefix("path="))
        .expect("PATH capture");
    assert!(path.split(':').any(|entry| entry == "/usr/sbin"));
    assert!(captured.contains("args=test --workspace --locked -- --test-threads=4\n"));
}

#[test]
fn quality_gate_trusts_only_the_exact_source_root_for_git_provenance() {
    let quality = read_workspace_file("scripts/quality.sh");

    for boundary in [
        "GIT_OPTIONAL_LOCKS=0 git",
        r#"-c safe.directory="$REPO_ROOT""#,
        r#"-c core.hooksPath=/dev/null"#,
        r#"-c core.fsmonitor=false"#,
        r#"-C "$REPO_ROOT""#,
    ] {
        assert!(quality.contains(boundary));
    }
    for command in [
        "source_git rev-parse --show-toplevel",
        "source_git rev-parse HEAD",
        "source_git status --porcelain=v1 --untracked-files=all",
        "source_git diff --binary HEAD --",
        "source_git ls-files --others --exclude-standard -z",
        "source_git hash-object --stdin",
    ] {
        assert!(
            quality.contains(command),
            "source provenance must execute {command} through the exact-root Git wrapper"
        );
    }
    assert!(!quality.contains("safe.directory=*"));
    assert!(!quality.contains("git config --global"));
}

#[cfg(unix)]
#[test]
fn quality_gate_accepts_complete_inherited_provenance_from_any_cwd() {
    let root = workspace_root();
    let fixture = tempfile::tempdir().expect("provenance caller directory");
    let expected_head = "a".repeat(40);
    let expected_fingerprint = "b".repeat(40);
    let output = Command::new(root.join("scripts/quality.sh"))
        .arg("provenance")
        .current_dir(fixture.path())
        .env("CATS_SOURCE_PROVENANCE_ROOT", "/host/exact-worktree")
        .env("CATS_SOURCE_PROVENANCE_HEAD", &expected_head)
        .env("CATS_SOURCE_PROVENANCE_DIRTY", "true")
        .env("CATS_SOURCE_PROVENANCE_FINGERPRINT", &expected_fingerprint)
        .output()
        .expect("run provenance probe");
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 provenance output");
    assert!(stdout.contains("source.root=/host/exact-worktree\n"));
    assert!(stdout.contains(&format!("source.head={expected_head}\n")));
    assert!(stdout.contains("source.dirty=true\n"));
    assert!(stdout.contains(&format!("source.fingerprint={expected_fingerprint}\n")));
}

#[cfg(unix)]
#[test]
fn quality_gate_rejects_partial_or_unresolvable_provenance() {
    let root = workspace_root();
    let partial = Command::new(root.join("scripts/quality.sh"))
        .arg("provenance")
        .env("CATS_SOURCE_PROVENANCE_ROOT", "/host/exact-worktree")
        .env_remove("CATS_SOURCE_PROVENANCE_HEAD")
        .env_remove("CATS_SOURCE_PROVENANCE_DIRTY")
        .env_remove("CATS_SOURCE_PROVENANCE_FINGERPRINT")
        .output()
        .expect("run partial provenance probe");
    assert!(!partial.status.success());
    assert!(String::from_utf8_lossy(&partial.stderr)
        .contains("overrides must set root, head, dirty and fingerprint together"));

    let fixture = tempfile::tempdir().expect("non-Git provenance fixture");
    let scripts = fixture.path().join("scripts");
    std::fs::create_dir(&scripts).expect("create scripts fixture");
    let copied = scripts.join("quality.sh");
    std::fs::copy(root.join("scripts/quality.sh"), &copied).expect("copy quality script");
    let unresolved = Command::new("bash")
        .arg(copied)
        .arg("provenance")
        .env_remove("CATS_SOURCE_PROVENANCE_ROOT")
        .env_remove("CATS_SOURCE_PROVENANCE_HEAD")
        .env_remove("CATS_SOURCE_PROVENANCE_DIRTY")
        .env_remove("CATS_SOURCE_PROVENANCE_FINGERPRINT")
        .output()
        .expect("run provenance outside Git");
    assert!(!unresolved.status.success());
}

#[cfg(unix)]
#[test]
fn production_postgres_probe_does_not_duplicate_a_known_positive() {
    let fixture = tempfile::tempdir().expect("schema probe fixture");
    let fake_kubectl = fixture.path().join("kubectl");
    let calls = fixture.path().join("calls");
    std::fs::write(
        &fake_kubectl,
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_KUBECTL_CALLS"
case " $* " in
  *" delete pod "*) exit 0 ;;
  *" run "*)
    if [[ " $* " == *" --attach "* ]]; then
      printf '10.20.18.70\n10.20.18.70\n'
    fi
    exit 0
    ;;
  *" get pod "*".status.phase"*) printf 'Succeeded' ;;
  *" logs "*) printf '10.20.18.70\n' ;;
  *" get pod "*"state.terminated.exitCode"*) printf '0' ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 97 ;;
esac
"#,
    )
    .expect("write fake kubectl");
    let mut permissions = std::fs::metadata(&fake_kubectl)
        .expect("fake kubectl metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_kubectl, permissions).expect("make fake kubectl executable");

    let inherited_path = std::env::var("PATH").expect("PATH");
    let output = Command::new("bash")
        .arg(workspace_root().join("deploy/aws/run-postgres-probe.sh"))
        .args([
            "fixture-kubeconfig",
            "cats",
            "owner-probe",
            "SELECT '10.20.18.70'",
        ])
        .env(
            "PATH",
            format!("{}:{inherited_path}", fixture.path().display()),
        )
        .env("FAKE_KUBECTL_CALLS", &calls)
        .output()
        .expect("run schema probe against known-positive fixture");

    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"10.20.18.70\n");
    let calls = std::fs::read_to_string(calls).expect("read fake kubectl calls");
    assert_eq!(
        calls.lines().filter(|call| call.contains(" logs ")).count(),
        1
    );
    assert!(calls.contains("SELECT '10.20.18.70'"));
    assert!(
        !calls.contains("--attach"),
        "attach fallback can duplicate the known-positive output: {calls}"
    );
}

#[cfg(unix)]
#[test]
fn reconciler_owner_selection_accepts_exact_pod_or_host_addresses_and_rejects_ambiguity() {
    let fixture = tempfile::tempdir().expect("owner selection fixture");
    let pods_path = fixture.path().join("pods.json");
    let pods = serde_json::json!({
        "items": [
            {
                "metadata": {"name": "controld-a", "uid": "uid-a"},
                "status": {
                    "phase": "Running",
                    "podIP": "10.0.0.11",
                    "hostIP": "192.0.2.11",
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "containerStatuses": [{"ready": true}]
                }
            },
            {
                "metadata": {"name": "controld-b", "uid": "uid-b"},
                "status": {
                    "phase": "Running",
                    "podIP": "10.0.0.12",
                    "hostIP": "192.0.2.12",
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "containerStatuses": [{"ready": true}]
                }
            },
            {
                "metadata": {"name": "controld-not-ready", "uid": "uid-c"},
                "status": {
                    "phase": "Running",
                    "podIP": "10.0.0.13",
                    "hostIP": "192.0.2.13",
                    "conditions": [{"type": "Ready", "status": "False"}],
                    "containerStatuses": [{"ready": false}]
                }
            }
        ]
    });
    std::fs::write(&pods_path, serde_json::to_vec(&pods).unwrap()).unwrap();

    let run = |owner_rows: &str, path: &Path| {
        let mut child = Command::new("bash")
            .arg(workspace_root().join("deploy/aws/select-reconciler-owner.sh"))
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run reconciler owner selector");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(owner_rows.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    for (owner, name, uid, kind) in [
        ("10.0.0.11\n", "controld-a", "uid-a", "pod-ip"),
        ("192.0.2.12\n", "controld-b", "uid-b", "host-ip"),
    ] {
        let output = run(owner, &pods_path);
        assert!(
            output.status.success(),
            "selector rejected {kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let selection: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(selection["name"], name);
        assert_eq!(selection["uid"], uid);
        assert_eq!(selection["address_kind"], kind);
    }

    for (owner_rows, diagnostic) in [
        ("", "owner_rows=0"),
        ("10.0.0.11\n10.0.0.11\n", "owner_rows=2"),
        ("10.0.0.13\n", "ready_union_matches=0"),
        ("203.0.113.99\n", "ready_union_matches=0"),
    ] {
        let output = run(owner_rows, &pods_path);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(diagnostic),
            "missing {diagnostic:?} in {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
    }

    let mut ambiguous = pods.clone();
    ambiguous["items"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "metadata": {"name": "controld-same-node", "uid": "uid-d"},
            "status": {
                "phase": "Running",
                "podIP": "10.0.0.14",
                "hostIP": "192.0.2.11",
                "conditions": [{"type": "Ready", "status": "True"}],
                "containerStatuses": [{"ready": true}]
            }
        }));
    let ambiguous_path = fixture.path().join("ambiguous.json");
    std::fs::write(&ambiguous_path, serde_json::to_vec(&ambiguous).unwrap()).unwrap();
    let output = run("192.0.2.11\n", &ambiguous_path);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("host_ip_matches=2"), "{stderr}");
    assert!(stderr.contains("address_union_matches=2"), "{stderr}");
    assert!(stderr.contains("ready_union_matches=2"), "{stderr}");

    let mut conflicting = pods.clone();
    conflicting["items"][1]["status"]["hostIP"] = serde_json::json!("10.0.0.11");
    let conflicting_path = fixture.path().join("conflicting.json");
    std::fs::write(&conflicting_path, serde_json::to_vec(&conflicting).unwrap()).unwrap();
    let output = run("10.0.0.11\n", &conflicting_path);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("pod_ip_matches=1"), "{stderr}");
    assert!(stderr.contains("host_ip_matches=1"), "{stderr}");
    assert!(stderr.contains("address_union_matches=2"), "{stderr}");
    assert!(stderr.contains("ready_union_matches=2"), "{stderr}");

    let strict_base = pods["items"][0].clone();
    let mut deleting_but_container_ready = strict_base.clone();
    deleting_but_container_ready["metadata"]["deletionTimestamp"] =
        serde_json::json!("2026-08-05T16:00:00Z");
    let mut pending_but_container_ready = strict_base.clone();
    pending_but_container_ready["status"]["phase"] = serde_json::json!("Pending");
    let mut pod_not_ready_but_container_ready = strict_base;
    pod_not_ready_but_container_ready["status"]["conditions"][0]["status"] =
        serde_json::json!("False");
    for (label, pod) in [
        ("deleting", deleting_but_container_ready),
        ("pending", pending_but_container_ready),
        ("pod-not-ready", pod_not_ready_but_container_ready),
    ] {
        let path = fixture.path().join(format!("strict-{label}.json"));
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"items": [pod]})).unwrap(),
        )
        .unwrap();
        let output = run("10.0.0.11\n", &path);
        assert!(!output.status.success(), "{label} Pod was selected");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("address_union_matches=1"), "{stderr}");
        assert!(stderr.contains("ready_union_matches=0"), "{stderr}");
    }

    let mut terminating = serde_json::json!({
        "items": [
            {
                "metadata": {
                    "name": "controld-old-owner",
                    "uid": "uid-old",
                    "deletionTimestamp": "2026-08-05T16:00:00Z"
                },
                "status": {
                    "phase": "Running",
                    "podIP": "10.0.0.21",
                    "hostIP": "192.0.2.21",
                    "conditions": [{"type": "Ready", "status": "False"}],
                    "containerStatuses": [{"ready": true}]
                }
            },
            {
                "metadata": {"name": "controld-ready-replacement", "uid": "uid-new"},
                "status": {
                    "phase": "Running",
                    "podIP": "10.0.0.22",
                    "hostIP": "192.0.2.21",
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "containerStatuses": [{"ready": true}]
                }
            }
        ]
    });
    let terminating_path = fixture.path().join("terminating.json");
    std::fs::write(&terminating_path, serde_json::to_vec(&terminating).unwrap()).unwrap();
    let output = run("192.0.2.21\n", &terminating_path);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("host_ip_matches=2"), "{stderr}");
    assert!(stderr.contains("address_union_matches=2"), "{stderr}");
    assert!(stderr.contains("ready_union_matches=1"), "{stderr}");

    terminating["items"].as_array_mut().unwrap().truncate(1);
    let terminating_only_path = fixture.path().join("terminating-only.json");
    std::fs::write(
        &terminating_only_path,
        serde_json::to_vec(&terminating).unwrap(),
    )
    .unwrap();
    let output = run("10.0.0.21\n", &terminating_only_path);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("address_union_matches=1"), "{stderr}");
    assert!(stderr.contains("ready_union_matches=0"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn pod_eviction_carries_pdb_and_uid_preconditions_and_rejects_a_replacement() {
    let fixture = tempfile::tempdir().expect("UID eviction fixture");
    let fake_bin = fixture.path().join("bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let fake_kubectl = fake_bin.join("kubectl");
    let request_path = fixture.path().join("delete-options.json");
    let delete_log = fixture.path().join("deleted");
    std::fs::write(
        &fake_kubectl,
        r#"#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == "--namespace cats create --raw /api/v1/namespaces/cats/pods/controld-a/eviction --filename -" ]]
cat >"$CATS_TEST_REQUEST"
jq -e --arg current "$CATS_TEST_CURRENT_UID" \
  '.kind == "Eviction" and .apiVersion == "policy/v1" and .deleteOptions.preconditions.uid == $current' \
  "$CATS_TEST_REQUEST" >/dev/null
touch "$CATS_TEST_DELETE_LOG"
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&fake_kubectl).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_kubectl, permissions).unwrap();

    let old_uid = "11111111-1111-4111-8111-111111111111";
    let new_uid = "22222222-2222-4222-8222-222222222222";
    let run = |current_uid: &str| {
        Command::new(workspace_root().join("deploy/aws/evict-pod-with-uid.sh"))
            .args(["cats", "controld-a", old_uid])
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    fake_bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("CATS_TEST_CURRENT_UID", current_uid)
            .env("CATS_TEST_REQUEST", &request_path)
            .env("CATS_TEST_DELETE_LOG", &delete_log)
            .output()
            .unwrap()
    };

    let stale = run(new_uid);
    assert!(!stale.status.success());
    assert!(
        !delete_log.exists(),
        "a same-name replacement must not be deleted"
    );
    let request: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&request_path).unwrap()).unwrap();
    assert_eq!(request["kind"], "Eviction");
    assert_eq!(request["apiVersion"], "policy/v1");
    assert_eq!(request["metadata"]["namespace"], "cats");
    assert_eq!(request["metadata"]["name"], "controld-a");
    assert_eq!(request["deleteOptions"]["preconditions"]["uid"], old_uid);
    assert_eq!(request["deleteOptions"]["propagationPolicy"], "Background");

    let exact = run(old_uid);
    assert!(
        exact.status.success(),
        "exact UID was rejected: {}",
        String::from_utf8_lossy(&exact.stderr)
    );
    assert!(delete_log.exists());
}

#[test]
fn production_database_clients_read_the_rotating_secret_files() {
    let terraform = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    for expected in [
        "--control-store-url-file",
        "url-file=/etc/cats/runtime/CATS_POSTGRES_URL",
        "CATS_USAGE_POSTGRES_URL_FILE",
        "mount_path = \"/etc/cats/runtime\"",
        "session-setup=${var.storage_postgres_session_setup}",
    ] {
        assert!(
            terraform.contains(expected),
            "production control-plane deployment is missing {expected:?}"
        );
    }
    assert!(
        !terraform.contains("sub_path   = \"CATS_POSTGRES_URL\""),
        "a Secret subPath mount never observes kubelet's atomic updates"
    );
}

#[test]
fn staged_proxy_cutover_rewrites_only_the_storage_database_host() {
    let directory = tempfile::tempdir().unwrap();
    let live = directory.path().join("live.json");
    let secret = directory.path().join("secret.json");
    std::fs::write(
        &live,
        r#"{
          "CATS_POSTGRES_URL": "postgresql://cats:old@direct.example:5432/cats?sslmode=verify-full",
          "CATS_USAGE_POSTGRES_URL": "postgresql://cats:old@direct.example:5432/cats?sslmode=verify-full"
        }"#,
    )
    .unwrap();
    std::fs::write(&secret, r#"{"password":"n@w:p/ss"}"#).unwrap();

    let output = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/swap-dsn-password.py"))
        .args([&live, &secret])
        .args([
            "--host",
            "CATS_POSTGRES_URL=cats-production-proxy.proxy.example",
            "CATS_POSTGRES_URL",
            "CATS_USAGE_POSTGRES_URL",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "DSN rewrite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rewritten: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        rewritten["CATS_POSTGRES_URL"],
        "postgresql://cats:n%40w%3Ap%2Fss@cats-production-proxy.proxy.example:5432/cats?sslmode=verify-full"
    );
    assert_eq!(
        rewritten["CATS_USAGE_POSTGRES_URL"],
        "postgresql://cats:n%40w%3Ap%2Fss@direct.example:5432/cats?sslmode=verify-full"
    );

    let invalid = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/swap-dsn-password.py"))
        .args([&live, &secret])
        .args([
            "--host",
            "CATS_POSTGRES_URL=https://attacker.example",
            "CATS_POSTGRES_URL",
        ])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid host override"));
}

#[test]
fn production_proxy_cutover_is_optional_and_fail_closed() {
    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    for expected in [
        "RDS_PROXY_ENDPOINT: ${{ vars.RDS_PROXY_ENDPOINT }}",
        "--host \"CATS_POSTGRES_URL=$RDS_PROXY_ENDPOINT\"",
        "storage_postgres_session_setup=server-verified",
        "storage_postgres_session_setup: $storage_postgres_session_setup",
    ] {
        assert!(
            workflow.contains(expected),
            "production workflow is missing proxy cutover contract {expected:?}"
        );
    }
    assert!(
        !workflow.contains("--host \"CATS_USAGE_POSTGRES_URL=$RDS_PROXY_ENDPOINT\""),
        "the bounded usage-store clients must retain the direct-RDS rollback path"
    );
}

#[test]
fn platform_bounds_postgres_connections_without_a_node_local_broker() {
    let database = read_workspace_file("deploy/aws/terraform/modules/platform-database/main.tf");
    for expected in [
        "resource \"aws_db_proxy\" \"this\"",
        "require_tls            = true",
        "resource \"aws_db_proxy_default_target_group\" \"this\"",
        "connection_borrow_timeout    = var.proxy_connection_borrow_timeout_seconds",
        "max_connections_percent      = var.proxy_max_connections_percent",
        "init_query                   = \"SET statement_timeout = '5s'; SET lock_timeout = '2s'\"",
        "resource \"aws_vpc_security_group_ingress_rule\" \"database_from_proxy\"",
        "actions   = [\"secretsmanager:GetSecretValue\"]",
        "actions   = [\"kms:Decrypt\"]",
        "variable = \"kms:ViaService\"",
        "DatabaseConnectionsCurrentlyBorrowed",
        "MaxDatabaseConnectionsAllowed",
        "ClientConnectionsSetupFailedAuth",
        "length(local.proxy_subnet_ids) >= 2",
    ] {
        assert!(
            database.contains(expected),
            "platform database is missing bounded-proxy contract {expected:?}"
        );
    }

    let adapter = read_workspace_file("adapters/metadata-store-postgres/src/lib.rs");
    for expected in [
        "SessionSetup::ServerVerified",
        "validate_server_session_settings(&settings)",
        "session-setup must be client or server-verified",
    ] {
        assert!(
            adapter.contains(expected),
            "metadata adapter is missing non-pinning proxy contract {expected:?}"
        );
    }
}

#[test]
fn production_control_plane_survives_one_pod_or_node_disruption() {
    let terraform = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    let variables =
        read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/variables.tf");
    let deployment = terraform
        .split("resource \"kubernetes_deployment_v1\" \"control_plane\"")
        .nth(1)
        .and_then(|rest| {
            rest.split("resource \"kubernetes_service_v1\" \"control_plane\"")
                .next()
        })
        .expect("control-plane Deployment block");

    for expected in [
        "replicas = var.control_plane_replicas",
        "type = \"RollingUpdate\"",
        "max_unavailable = \"0\"",
        "termination_grace_period_seconds = local.public_target_termination_grace_period_seconds",
        "pre_stop {",
        "command = [\"/bin/sh\", \"-c\", \"sleep ${local.public_target_pre_stop_delay_seconds}\"]",
        "pod_anti_affinity {",
        "required_during_scheduling_ignored_during_execution {",
        "topology_key       = \"kubernetes.io/hostname\"",
        "when_unsatisfiable = \"DoNotSchedule\"",
    ] {
        assert!(
            deployment.contains(expected),
            "control-plane Deployment is missing {expected:?}"
        );
    }
    let required_anti_affinity = deployment
        .split("required_during_scheduling_ignored_during_execution {")
        .nth(1)
        .and_then(|rest| rest.split("topology_spread_constraint {").next())
        .expect("required control-plane hostname anti-affinity block");
    for expected in [
        "topology_key = \"kubernetes.io/hostname\"",
        "\"app.kubernetes.io/name\" = \"cats-controld\"",
    ] {
        assert!(
            required_anti_affinity.contains(expected),
            "required control-plane anti-affinity is missing {expected:?}"
        );
    }
    for expected in [
        "public_target_pre_stop_delay_seconds           = 15",
        "public_target_termination_grace_period_seconds = 60",
        "condition     = local.public_target_pre_stop_delay_seconds + 30 <= local.public_target_termination_grace_period_seconds",
    ] {
        assert!(
            terraform.contains(expected),
            "control-plane target drain is missing {expected:?}"
        );
    }
    assert!(variables.contains("var.control_plane_replicas >= 2"));
    assert!(
        terraform.contains("resource \"kubernetes_pod_disruption_budget_v1\" \"control_plane\"")
    );
    assert!(terraform.contains("min_available = \"1\""));
    assert!(
        !deployment.contains("type = \"Recreate\""),
        "Recreate deliberately creates a total control-plane outage"
    );
}

#[test]
fn production_endpoint_ingress_stays_absent_until_route_grant_v2() {
    let terraform = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    let variables =
        read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/variables.tf");
    assert!(terraform.contains("Public Endpoint ingress stays absent"));
    assert!(terraform.contains("for host in var.control_plane_hosts"));
    assert!(!terraform.contains("endpoint_wildcard_host"));
    assert!(!variables.contains("endpoint_wildcard_host"));

    let application =
        read_workspace_file("deploy/aws/terraform/stacks/production-application/main.tf");
    assert!(application.contains("dns_hosts = toset(var.control_plane_hosts)"));
    assert!(!application.contains("endpoint_wildcard_host"));

    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    assert!(workflow.contains("for deployment in cats-controld"));
    assert!(!workflow.contains("for deployment in cats-controld cats-gatewayd"));
}

#[test]
fn production_ha_drill_deletes_only_the_elected_reconciler_under_a_guard() {
    let workflow = read_workspace_file(".github/workflows/verify-control-plane-ha.yml");
    for expected in [
        "workflow_dispatch:",
        "READ_ONLY_CONTROL_PLANE_LEADER_DIAGNOSTIC",
        "DELETE_ONE_CATS_CONTROLD_LEADER",
        "github.ref == 'refs/heads/main'",
        "actions/checkout@v4",
        "inputs.mode == 'diagnose'",
        ".status.hostIP",
        "disruptionsAllowed",
        "l.classid=hashtext(current_schema())::oid",
        "l.objid=420201",
        "l.objsubid=2",
        "COALESCE(host(a.client_addr), '<local>')",
        "deploy/aws/run-postgres-probe.sh",
        "deploy/aws/select-reconciler-owner.sh",
        "deploy/aws/evict-pod-with-uid.sh cats \"$target\" \"$target_uid\"",
        "reconciler leadership changed before the disruption boundary",
        ".metadata.deletionTimestamp == null",
        ".status.phase == \"Running\"",
        "https://cats.run/healthz",
        "deploy/aws/probe-public-endpoint.py",
        "deploy/aws/wait-for-public-probe-baseline.py",
        "deploy/aws/retain-bounded-jsonl.py",
        "deploy/aws/summarize-control-plane-log.py",
        "deploy/aws/terminate-process-tree.py",
        "--interval-ms 250",
        "--max-in-flight 16",
        "--max-lines 2000",
        "--max-bytes 1048576",
        "endpointslices.discovery.k8s.io",
        "--output-watch-events",
        "actions/upload-artifact@v4",
        "if: always() && inputs.mode == 'disrupt'",
        "rollout status deployment/cats-controld",
        "All 240 public health probes succeeded",
        "reconciler leadership did not move",
    ] {
        assert!(
            workflow.contains(expected),
            "production HA drill is missing {expected:?}"
        );
    }
    let checkout = workflow
        .find("actions/checkout@v4")
        .expect("HA drill checks out its dispatched revision");
    let owner_probe = workflow
        .find("deploy/aws/run-postgres-probe.sh")
        .expect("HA drill invokes the PostgreSQL probe runner");
    assert!(
        checkout < owner_probe,
        "the repository must be checked out before invoking its PostgreSQL probe runner"
    );
    assert!(!workflow.contains("--force"));
    assert!(!workflow.contains("--grace-period=0"));
    assert!(!workflow.contains("scale deployment"));
    assert!(!workflow.contains("--attach"));
    assert!(!workflow.contains("tr -d '[:space:]' <<<\"$leader_ip\""));
    assert_eq!(
        workflow
            .matches("COALESCE(host(a.client_addr), '<local>')")
            .count(),
        2,
        "both destructive owner queries must normalize PostgreSQL inet values without guessing at CIDR text"
    );
    assert_eq!(
        workflow.matches("a.client_addr::text").count(),
        1,
        "CIDR text is diagnostic evidence only and must not feed Pod identity selection"
    );
    assert_eq!(
        workflow.matches("deploy/aws/run-postgres-probe.sh").count(),
        4,
        "diagnostic, initial, boundary-confirmation, and post-disruption probes must avoid attach replay"
    );
    assert_eq!(
        workflow.matches("if: inputs.mode == 'disrupt'").count(),
        2,
        "destructive and post-disruption steps must require disrupt mode"
    );
    assert_eq!(
        workflow
            .matches("deploy/aws/select-reconciler-owner.sh")
            .count(),
        3,
        "all owner probes must use the same exact Pod-or-host selector"
    );
    assert!(workflow.contains("observed_uid"));
    assert!(workflow.contains("target_uid"));
    let readiness = workflow
        .find("deploy/aws/wait-for-public-probe-baseline.py")
        .expect("HA drill has an executable public-probe readiness gate");
    let uid_guard = workflow
        .find("observed_uid=\"")
        .expect("HA drill rechecks the selected Pod UID");
    let eviction = workflow
        .find("deploy/aws/evict-pod-with-uid.sh cats \"$target\" \"$target_uid\"")
        .expect("HA drill uses guarded Eviction");
    assert!(
        readiness < uid_guard && uid_guard < eviction,
        "a completed healthy public attempt must gate the UID check and Eviction"
    );
    assert!(
        !workflow.contains("--prefix"),
        "raw application log text must not be retained as HA evidence"
    );
    assert!(
        !workflow.contains("for attempt in $(seq 1 240)"),
        "a serial curl loop becomes blind for the duration of a slow request"
    );
}

#[cfg(unix)]
#[test]
fn production_ha_probe_models_stale_target_drain_ordering() {
    let _fixture_guard = ha_fixture_guard();
    let probe = read_workspace_file("deploy/aws/probe-public-endpoint.py");
    for expected in [
        "asyncio.Semaphore",
        "scheduled_monotonic",
        "schedule_lag_ms",
        "time_namelookup",
        "time_connect",
        "time_appconnect",
        "time_starttransfer",
        "time_total",
        "remote_ip",
        "headers",
        "HEADER_POLICY",
        "DIGEST_HEADER_ALLOWLIST",
        "SIGTERM",
        "SIGINT",
        "configured_count",
        "scheduled_count",
        "started_count",
        "completed_count",
        "missing_count",
        "attempt_incomplete",
        r#""/dev/null""#,
    ] {
        assert!(
            probe.contains(expected),
            "fixed-rate HA probe is missing {expected:?}"
        );
    }

    let output = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/probe-public-endpoint-fixture.py"))
        .arg("--probe")
        .arg(workspace_root().join("deploy/aws/probe-public-endpoint.py"))
        .output()
        .expect("run the retained-stale-target probe fixture");
    assert!(
        output.status.success(),
        "stale-target fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("fixture output is UTF-8");
    assert!(stdout.contains("unsafe immediate exit: failures observed"));
    assert!(stdout.contains("drained exit: all probes succeeded"));
}

#[cfg(unix)]
#[test]
fn production_ha_probe_signal_finalizer_accounts_for_every_attempt() {
    let _fixture_guard = ha_fixture_guard();
    let output = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/probe-public-endpoint-signal-fixture.py"))
        .arg("--probe")
        .arg(workspace_root().join("deploy/aws/probe-public-endpoint.py"))
        .output()
        .expect("run the HA probe signal-finalizer fixture");
    assert!(
        output.status.success(),
        "signal-finalizer fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("no orphan curl"));

    let interrupt = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/probe-public-endpoint-signal-fixture.py"))
        .arg("--probe")
        .arg(workspace_root().join("deploy/aws/probe-public-endpoint.py"))
        .args(["--signal", "SIGINT"])
        .output()
        .expect("run the HA probe SIGINT-finalizer fixture");
    assert!(
        interrupt.status.success(),
        "SIGINT-finalizer fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&interrupt.stdout),
        String::from_utf8_lossy(&interrupt.stderr)
    );
    assert!(String::from_utf8_lossy(&interrupt.stdout).contains("SIGINT finalizer"));
}

#[cfg(unix)]
#[test]
fn production_ha_probe_readiness_gate_precedes_eviction() {
    let _fixture_guard = ha_fixture_guard();
    let output = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/public-probe-readiness-fixture.py"))
        .arg("--probe")
        .arg(workspace_root().join("deploy/aws/probe-public-endpoint.py"))
        .arg("--wait-helper")
        .arg(workspace_root().join("deploy/aws/wait-for-public-probe-baseline.py"))
        .output()
        .expect("run the public-probe readiness fixture");
    assert!(
        output.status.success(),
        "readiness fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("zero Evictions before readiness, exactly one after"));
}

#[cfg(unix)]
#[test]
fn production_ha_evidence_is_bounded_and_non_sensitive() {
    let _fixture_guard = ha_fixture_guard();
    let output = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/ha-evidence-boundary-fixture.py"))
        .arg("--bounded-jsonl")
        .arg(workspace_root().join("deploy/aws/retain-bounded-jsonl.py"))
        .arg("--log-summarizer")
        .arg(workspace_root().join("deploy/aws/summarize-control-plane-log.py"))
        .output()
        .expect("run the HA evidence boundary fixture");
    assert!(
        output.status.success(),
        "evidence-boundary fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("raw log sentinel excluded"));

    let cleanup = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/process-tree-cleanup-fixture.py"))
        .arg("--helper")
        .arg(workspace_root().join("deploy/aws/terminate-process-tree.py"))
        .output()
        .expect("run the HA evidence process-tree cleanup fixture");
    assert!(
        cleanup.status.success(),
        "process-tree cleanup fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cleanup.stdout),
        String::from_utf8_lossy(&cleanup.stderr)
    );
    assert!(String::from_utf8_lossy(&cleanup.stdout).contains("no orphan"));
}

#[cfg(unix)]
#[test]
fn production_ha_probe_rejects_invalid_scheduling_inputs() {
    let probe = workspace_root().join("deploy/aws/probe-public-endpoint.py");
    let fixture = tempfile::tempdir().expect("HA probe argument fixture");
    let invalid_cases: &[&[&str]] = &[
        &["--url", "https://user:password@cats.run/healthz"],
        &["--url", "https://cats.run/healthz", "--count", "0"],
        &["--url", "https://cats.run/healthz", "--max-in-flight", "1"],
        &[
            "--url",
            "https://cats.run/healthz",
            "--expected-status",
            "99",
        ],
    ];

    for (index, arguments) in invalid_cases.iter().enumerate() {
        let output = Command::new("python3")
            .arg(&probe)
            .args(*arguments)
            .arg("--output-dir")
            .arg(fixture.path().join(index.to_string()))
            .output()
            .expect("run HA probe invalid-input case");
        assert!(
            !output.status.success(),
            "invalid HA probe arguments unexpectedly succeeded: {arguments:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn production_ha_watches_wait_for_known_positive_events() {
    let workflow = read_workspace_file(".github/workflows/verify-control-plane-ha.yml");
    assert!(workflow.contains("deploy/aws/wait-for-evidence-streams.sh"));
    assert!(workflow.contains("watch_pids"));
    assert!(workflow.contains("pods-timeline.jsonl"));
    assert!(workflow.contains("endpointslices-timeline.jsonl"));
    assert!(
        !workflow.contains("# Give each stream time to emit its known-positive initial state"),
        "watch readiness must not depend on a fixed sleep"
    );

    let output = Command::new("bash")
        .arg(workspace_root().join("deploy/aws/watch-readiness-fixture.sh"))
        .arg("--waiter")
        .arg(workspace_root().join("deploy/aws/wait-for-evidence-streams.sh"))
        .output()
        .expect("run the delayed watch-readiness fixture");
    assert!(
        output.status.success(),
        "watch-readiness fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("fixture output is UTF-8");
    assert!(stdout.contains("delayed streams: ready"));
    assert!(stdout.contains("early watcher exit: rejected"));
    assert!(stdout.contains("silent watcher timeout: rejected"));
}

#[test]
fn noninteractive_worker_bootstrap_defines_root_home_before_toolchain_use() {
    for path in [
        "deploy/aws/metal/install-worker.sh",
        "deploy/metal/build-guest-image.sh",
    ] {
        let script = read_workspace_file(path);
        let lines: Vec<_> = script.lines().collect();
        let root_guard = lines
            .iter()
            .position(|line| line.contains("[[ $EUID -eq 0 ]]"))
            .expect("root guard");
        let home_default = lines
            .iter()
            .position(|line| line.contains(r#"export HOME="${HOME:-/root}""#))
            .unwrap_or_else(|| panic!("{path} does not define HOME for a non-login root shell"));
        let toolchain = lines
            .iter()
            .position(|line| {
                let line = line.trim_start();
                !line.starts_with('#') && (line.contains("cargo ") || line.contains("rustup "))
            })
            .unwrap_or_else(|| panic!("{path} does not invoke the Rust toolchain"));
        assert!(
            root_guard < home_default && home_default < toolchain,
            "{path} must validate root, default HOME, then invoke rustup/cargo"
        );
    }
}

#[test]
fn worker_installation_owns_all_runtime_socket_roots() {
    let tmpfiles = read_workspace_file("deploy/metal/tmpfiles/cats-vmm.conf");
    for declaration in [
        "d /run/cats/vmm-v1 0700 root root -",
        "d /run/cats/blockd-v1 0700 root root -",
    ] {
        assert!(
            tmpfiles.lines().any(|line| line == declaration),
            "runtime tmpfiles contract lost {declaration:?}"
        );
    }

    let provisioned_state_namespaces = "vmm-socket-receipts vmm-launch-v1 blockd-socket-intents-v1";

    let provisioner = read_workspace_file("deploy/aws/metal/provision-vmm-socket-namespaces.sh");
    assert!(
        provisioner.contains(provisioned_state_namespaces),
        "identity-selected state provisioning lost the durable blockd intent namespace"
    );
    let create = provisioner
        .find("systemd-tmpfiles --create /usr/lib/tmpfiles.d/cats-vmm.conf")
        .expect("runtime tmpfiles creation");
    for preflight in [
        "validate_or_absent_installed_runtime_socket_root /run/cats/vmm-v1 VMM",
        "validate_or_absent_installed_runtime_socket_root /run/cats/blockd-v1 blockd",
    ] {
        let validate = provisioner
            .find(preflight)
            .unwrap_or_else(|| panic!("runtime provisioner lost {preflight:?}"));
        assert!(
            validate < create,
            "tmpfiles may not repair a foreign runtime root"
        );
    }
    for validation in [
        "validate_installed_runtime_socket_root /run/cats/vmm-v1 VMM",
        "validate_installed_runtime_socket_root /run/cats/blockd-v1 blockd",
    ] {
        let validate = provisioner
            .find(validation)
            .unwrap_or_else(|| panic!("runtime provisioner lost {validation:?}"));
        assert!(
            create < validate,
            "runtime root was validated before creation"
        );
    }
    for invariant in [
        "[[ -d $directory && ! -L $directory ]]",
        "stat -c '%u:%g:%a' \"$directory\"",
        "== 0:0:700",
    ] {
        assert!(
            provisioner.contains(invariant),
            "runtime root validation lost {invariant:?}"
        );
    }

    for bootstrap in [
        "deploy/aws/metal/install-worker.sh",
        "deploy/metal/install.sh",
    ] {
        let source = read_workspace_file(bootstrap);
        let install = source
            .find("/usr/lib/tmpfiles.d/cats-vmm.conf")
            .unwrap_or_else(|| panic!("{bootstrap} does not install runtime tmpfiles"));
        let provision = source
            .find("\"$PREFIX/bin/provision-vmm-socket-namespaces\"")
            .or_else(|| source.find("\"$CATS_PREFIX/bin/provision-vmm-socket-namespaces\""))
            .unwrap_or_else(|| panic!("{bootstrap} does not run the runtime provisioner"));
        assert!(
            install < provision,
            "{bootstrap} must install tmpfiles before provisioning runtime roots"
        );
    }
}

#[cfg(unix)]
#[test]
fn worker_bootstrap_validates_and_installs_its_route_grant_key_before_mutation() {
    let script = read_workspace_file("deploy/aws/metal/install-worker.sh");
    let required = script
        .find("CATS_ROUTE_GRANT_PUBLIC_KEY_FILE is required")
        .expect("required Route Grant key input");
    let validator = script
        .find("validate-route-grant-public-key.sh")
        .expect("cryptographic Route Grant key validator");
    let first_package_mutation = script.find("apt-get update -q").expect("package mutation");
    let key_install = script
        .find("install -o root -g root -m 0644 \"$ROUTE_GRANT_PUBLIC_KEY_STAGE\"")
        .expect("root-owned Route Grant key install");
    let key_destination = script
        .find("/etc/cats/route-grant-public.pem")
        .expect("service Route Grant key path");
    let environment_branch = script
        .find("if [[ -f /etc/cats/worker.env ]]")
        .expect("existing worker.env branch");
    assert!(
        required < validator
            && validator < first_package_mutation
            && key_install <= key_destination
            && key_destination < environment_branch,
        "missing/malformed key input must fail before package/file/service mutation, and a valid key must be installed before either worker.env branch"
    );
    assert!(script.contains("trap cleanup_route_grant_key EXIT"));

    let validator = workspace_root().join("deploy/aws/metal/validate-route-grant-public-key.sh");
    let valid = Command::new(&validator)
        .arg(workspace_root().join("tests/fixtures/route_grant_public_ed25519.pem"))
        .output()
        .expect("validate Ed25519 public fixture");
    assert!(valid.status.success());
    for invalid in [
        "tests/fixtures/route_grant_private_ed25519.pem",
        "Cargo.toml",
    ] {
        let output = Command::new(&validator)
            .arg(workspace_root().join(invalid))
            .output()
            .unwrap_or_else(|error| panic!("validate {invalid}: {error}"));
        assert!(!output.status.success(), "accepted invalid key {invalid}");
    }
}

#[test]
fn agent_registration_deployments_share_one_canonical_release_receipt() {
    let receipt_argument =
        "--guest-runtime-profile-receipt-file /opt/cats/release/guest-runtime-profile.v1.json";
    for unit in [
        "deploy/metal/systemd/cats-controld.service",
        "deploy/metal/systemd/cats-noded.service",
        "deploy/aws/metal/cats-worker.service",
    ] {
        let source = read_workspace_file(unit);
        assert!(
            source.contains(receipt_argument),
            "{unit} lost the exact installed release receipt"
        );
        if unit.contains("noded") || unit.contains("worker") {
            for forbidden in ["--node-id", "--state-dir", "--ch-kernel", "--ch-initramfs"] {
                assert!(
                    !source.contains(forbidden),
                    "{unit} regained forbidden identity or Guest-byte override {forbidden}"
                );
            }
        }
    }

    let kubernetes = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    assert!(kubernetes.contains("\"--guest-runtime-profile-receipt-file\","));
    assert!(kubernetes.contains("\"/opt/cats/release/guest-runtime-profile.v1.json\","));

    let control_image = read_workspace_file("deploy/aws/Dockerfile.control-plane");
    for copy in [
        "guest-runtime-release.v1/guest-runtime-profile.v1.json /opt/cats/release/guest-runtime-profile.v1.json",
        "guest-runtime-release.v1/manifest.v1.json /opt/cats/release/guest-runtime-release-manifest.v1.json",
    ] {
        assert!(control_image.contains(copy), "Control image lost {copy:?}");
    }
    let worker_image = read_workspace_file("deploy/aws/Dockerfile.worker-artifact");
    assert!(worker_image.contains("COPY guest-runtime-release.v1 /guest-runtime-release.v1"));
    let noded = read_workspace_file("cmd/noded/src/main.rs");
    assert!(noded.contains("load_installed_guest_runtime_profile_receipt"));
    assert!(noded.contains("validate_installed_node_guest_runtime"));
    assert!(noded.contains("spawn_signed_runtime_cutover"));

    let workflow = read_workspace_file(".github/workflows/release.yml");
    assert_eq!(
        workflow.matches("guest-runtime-release:\n").count(),
        1,
        "the workflow must have one Guest release producer"
    );
    assert!(workflow.contains("RELEASE_OUT=\"$PWD/guest-runtime-release.v1\""));
    assert_eq!(
        workflow.matches("needs: guest-runtime-release").count(),
        2,
        "Control and Node artifacts must consume the same build job"
    );
    assert_eq!(
        workflow.matches("name: guest-runtime-release-v1").count(),
        3,
        "one upload and exactly two consumers must name the same artifact"
    );
    assert!(
        workflow.contains("tar --owner=0 --group=0 --numeric-owner -C worker-out"),
        "the worker archive must preserve the root-owned release member contract"
    );
    for guide in ["deploy/aws/README.md", "deploy/metal/README.md"] {
        let guide = read_workspace_file(guide);
        for composition_gate in [
            "not a standalone deployable release",
            "A20 signed Desired",
            "/v1/nodes/heartbeat",
            "shared-bearer heartbeat",
            "eleven",
            "readiness stays closed",
            "zero runtime effect",
        ] {
            assert!(
                guide.contains(composition_gate),
                "runtime cutover guide lost composition blocker {composition_gate:?}"
            );
        }
    }
}

#[test]
fn runtime_node_authority_deployments_pin_exact_trust_artifact_and_shutdown_window() {
    let argument =
        "--runtime-provisioner-trust-file /etc/cats/identity/runtime-provisioner-trust.v1.json";
    let metal = read_workspace_file("deploy/metal/systemd/cats-controld.service");
    assert!(metal.contains(argument));
    assert!(metal.contains("TimeoutStopSec=35s"));

    let kubernetes = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    for expected in [
        "\"--runtime-provisioner-trust-file\",",
        "\"/etc/cats/identity/runtime-provisioner-trust.v1.json\",",
        "resource \"kubernetes_config_map_v1\" \"runtime_provisioner_trust\"",
        "mount_path = \"/etc/cats/identity/runtime-provisioner-trust.v1.json\"",
        "sub_path   = \"runtime-provisioner-trust.v1.json\"",
        "public_target_termination_grace_period_seconds = 60",
        "public_target_pre_stop_delay_seconds + 30 <= local.public_target_termination_grace_period_seconds",
    ] {
        assert!(
            kubernetes.contains(expected),
            "production A23 composition lost {expected:?}"
        );
    }
    let variables =
        read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/variables.tf");
    assert!(variables.contains("variable \"runtime_provisioner_trust_bundle_json\""));
    assert!(variables.contains("<= 16384"));
    let image = read_workspace_file("deploy/aws/Dockerfile.control-plane");
    assert!(image.contains("install -d -o 0 -g 0 -m 0755 /etc/cats/identity"));
    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    for expected in [
        "RUNTIME_PROVISIONER_TRUST_BUNDLE_B64",
        "$RUNNER_TEMP/runtime-provisioner-trust.v1.json",
        "runtime_provisioner_trust_bundle_json: $runtime_provisioner_trust_bundle_json",
    ] {
        assert!(workflow.contains(expected));
    }
}

#[test]
fn worker_release_install_is_closed_durable_and_identity_fail_closed() {
    let installer = read_workspace_file("deploy/aws/metal/install-guest-runtime-release.sh");
    for invariant in [
        "actual != expected",
        "actual_directories != {\"guest\"}",
        "metadata.st_nlink != 1",
        "metadata.st_uid != required_uid",
        "stat.S_IMODE(metadata.st_mode) != 0o644",
        "sync_release_tree \"$destination\"",
        "mv -T -- \"$incomplete\" \"$target_set\"",
        "previous_id=$(persist_active_set)",
        "write_activation \"$release_id\" \"$previous_id\"",
        "recover_activation",
        "write_start_authorization \"$activation_incoming\"",
        "load_start_authorization \"$activation_incoming\"",
        "require_service_stopped",
        "require_service_active",
        "activation-parent-fsync",
        "activation-before-journal-replace",
        "active-layout-parent-fsync:cats-root",
        "trap prepare_rollback ERR",
        "active-rename:$label",
    ] {
        assert!(
            installer.contains(invariant),
            "release installer lost {invariant:?}"
        );
    }
    let kernel_activation = installer
        .find("\"$set/guest/vmlinuz\" \"$active_guest_root/vmlinuz\" kernel")
        .expect("kernel activation");
    let manifest_activation = installer
        .find("\"$set/manifest.v1.json\" \\")
        .expect("manifest activation");
    assert!(
        kernel_activation < manifest_activation,
        "the manifest is the active-set commit marker and must be renamed last"
    );

    for bootstrap in [
        "deploy/aws/metal/install-worker.sh",
        "deploy/metal/install.sh",
    ] {
        let source = read_workspace_file(bootstrap);
        let required = source
            .find("CATS_GUEST_RUNTIME_RELEASE_DIR must name the qualified guest-runtime-release.v1 payload")
            .expect("required shared release input");
        let verify = source
            .find("\"$release_installer\" verify")
            .expect("release verification");
        let prepare = source
            .find("\"$release_installer\" prepare")
            .expect("release preparation");
        let readiness = source
            .find("cats_wait_for_registered_node")
            .expect("registration-backed readiness");
        let authorize = source
            .find("cats_begin_candidate_lifetime")
            .expect("post-mutation start authorization and watchdog");
        let commit = source
            .find("cats_commit_candidate \"$release_installer\"")
            .expect("release commit");
        assert!(
            required < verify
                && verify < prepare
                && prepare < authorize
                && authorize < readiness
                && readiness < commit
        );
        assert!(source.contains("cats_acquire_worker_deployment_lock"));
        assert!(source.contains("validate-node-identity-installation.sh"));
        for boundary in [
            "after-installer-return",
            "after-daemon-reload",
            "after-authorize-worker-start",
            "after-start-worker",
            "after-registration-readiness",
            "after-release-commit",
        ] {
            assert!(
                source.contains(&format!("cats_worker_deployment_crash_probe {boundary}")),
                "{bootstrap} lost outer transaction crash boundary {boundary}"
            );
        }
        assert!(source.contains("cats_stop_node_service"));
        assert!(source.contains("\"$release_installer\" rollback"));
        for forbidden in ["169.254.169.254", "CATS_NODE_ID=", "build-guest-image.sh"] {
            assert!(
                !source.contains(forbidden),
                "{bootstrap} regained Host-local identity/release synthesis {forbidden:?}"
            );
        }
    }

    let identity_validator =
        read_workspace_file("deploy/aws/metal/validate-node-identity-installation.sh");
    for exact in [
        "identity_dir=/etc/cats/identity",
        "node-identity.v1.json",
        "node-registration-key.pem",
        "node-registration-credential-id",
        "0:0:700",
        "0:0:600:1",
    ] {
        assert!(identity_validator.contains(exact));
    }

    let terraform =
        read_workspace_file("deploy/aws/terraform/modules/metal-worker-deployment/main.tf");
    let archive_listing = terraform.find("tar --zstd -tf").expect("archive preflight");
    let archive_extract = terraform.find("tar --zstd -xf").expect("archive extract");
    let release_verify = terraform
        .find("install-guest-runtime-release.sh\" verify")
        .expect("staged release verification");
    let identity_validate = terraform
        .find("validate-node-identity-installation.sh\"")
        .expect("staged identity validation");
    let early_idle_guard = terraform
        .find("require-idle-worker.sh\"")
        .expect("drained worker guard");
    let deployment_lock = terraform
        .find("cats_acquire_worker_deployment_lock")
        .expect("Host deployment lock");
    let locked_metering = terraform[deployment_lock..]
        .find("metering_root=\"$(cats_worker_metering_root cats-worker)\"")
        .map(|offset| deployment_lock + offset)
        .expect("metering cgroup recomputation under the Host lock");
    let locked_idle_guard = terraform[locked_metering..]
        .find("require-idle-worker.sh\"")
        .map(|offset| locked_metering + offset)
        .expect("physical idle recheck under the Host lock");
    let stop = terraform[locked_idle_guard..]
        .find("cats_gate_node_service cats-worker")
        .map(|offset| locked_idle_guard + offset)
        .expect("masked worker stop");
    let prepare = terraform[stop..]
        .find("\"$release_installer\" prepare")
        .map(|offset| stop + offset)
        .expect("durable release prepare");
    let first_install = terraform
        .find("install -D -m 0755 \"$stage_path/cats-noded\"")
        .expect("first installed byte");
    assert!(
        archive_listing < archive_extract
            && archive_extract < release_verify
            && release_verify < identity_validate,
        "nothing from the empty stage may execute before verified extraction"
    );
    let authorize = terraform
        .find("cats_begin_candidate_lifetime cats-worker \"$release_installer\"")
        .expect("durable post-mutation start authorization and watchdog");
    let start = terraform
        .find("systemctl start cats-worker")
        .expect("candidate worker start");
    let readiness = terraform
        .find("cats_wait_for_registered_node cats-worker")
        .expect("registration-backed readiness");
    let commit = terraform
        .find("cats_commit_candidate \"$release_installer\"")
        .expect("release commit");
    assert!(
        first_install < authorize && authorize < start && start < readiness && readiness < commit
    );
    assert!(
        identity_validate < early_idle_guard
            && early_idle_guard < deployment_lock
            && deployment_lock < locked_metering
            && locked_metering < locked_idle_guard
            && locked_idle_guard < stop
            && stop < prepare
            && prepare < first_install
    );
    for forbidden in ["169.254.169.254", "CATS_NODE_ID=", "--node-id"] {
        assert!(
            !terraform.contains(forbidden),
            "Terraform regained derived Node identity {forbidden:?}"
        );
    }
    for boundary in [
        "after-installer-return",
        "after-update-guest-seed",
        "after-authorize-worker-start",
        "after-start-worker",
        "after-registration-readiness",
        "after-release-commit",
    ] {
        assert!(
            terraform.contains(&format!("cats_worker_deployment_crash_probe {boundary}")),
            "Terraform lost outer transaction crash boundary {boundary}"
        );
    }
}

#[cfg(unix)]
#[test]
fn guest_release_shell_entrypoints_parse() {
    for script in [
        "deploy/aws/metal/install-guest-runtime-release.sh",
        "deploy/aws/metal/install-worker.sh",
        "deploy/aws/metal/worker-deployment-transaction.sh",
        "deploy/aws/metal/validate-node-identity-installation.sh",
        "deploy/metal/build-guest-image.sh",
        "deploy/metal/install.sh",
    ] {
        let output = Command::new("bash")
            .args(["-n", script])
            .current_dir(workspace_root())
            .output()
            .unwrap_or_else(|error| panic!("parse {script}: {error}"));
        assert!(
            output.status.success(),
            "{script} is not valid Bash: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
