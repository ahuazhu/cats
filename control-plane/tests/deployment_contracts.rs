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
fn production_metal_fleet_keeps_stable_addresses_and_one_explicit_root_cutover() {
    let main = read_workspace_file("deploy/aws/terraform/stacks/platform/main.tf");
    let variables = read_workspace_file("deploy/aws/terraform/stacks/platform/variables.tf");
    let outputs = read_workspace_file("deploy/aws/terraform/stacks/platform/outputs.tf");
    let platform_example =
        read_workspace_file("deploy/aws/terraform/stacks/platform/platform.tfvars.example");
    let infrastructure_example = read_workspace_file(
        "deploy/aws/terraform/stacks/production-infrastructure/production.tfvars.example",
    );
    let runbook = read_workspace_file("deploy/aws/terraform/README.md");

    for contract in [
        "for_each = var.metal_workers",
        "from = aws_instance.metal_worker[0]",
        "to   = aws_instance.metal_worker[\"metal-2\"]",
        "from = aws_instance.metal_worker[1]",
        "to   = aws_instance.metal_worker[\"metal-1\"]",
        "encrypted             = each.value.root_volume_encrypted",
    ] {
        assert!(
            main.contains(contract),
            "missing metal fleet contract: {contract}"
        );
    }
    assert!(
        !main.contains("root_block_device]"),
        "root encryption drift must be visible to the reviewed maintenance plan",
    );
    assert!(
        variables.contains("variable \"metal_workers\"")
            && variables.contains("root_volume_encrypted = bool")
            && variables.contains("worker.root_volume_encrypted || name == \"metal-2\""),
        "workers need stable keys and an explicit per-worker root encryption target",
    );
    let worker_resource = main
        .split_once("resource \"aws_instance\" \"metal_worker\"")
        .and_then(|(_, source)| source.split_once("# Preserve the exact imported"))
        .map(|(source, _)| source)
        .expect("metal worker resource and address migration boundary");
    assert!(
        !worker_resource.contains("prevent_destroy = true"),
        "an unconditional prevent_destroy would hide the reviewed root replacement plan",
    );
    assert!(
        outputs.contains("for name, worker in aws_instance.metal_worker : name => worker.id"),
        "platform must emit the exact stable-name to instance-ID deployment input",
    );

    for source in [&platform_example, &infrastructure_example] {
        assert!(
            source.contains("\"metal-2\"") && source.contains("\"metal-1\""),
            "both production workers must be present in every fleet handoff example",
        );
    }
    assert!(
        platform_example.contains("root_volume_encrypted = false")
            && platform_example.contains("root_volume_encrypted = true"),
        "the ordinary plan must match legacy metal-2 while keeping metal-1 encrypted",
    );
    for contract in [
        "metal-2-root-encryption.tfplan",
        "aws_instance.metal_worker[\"metal-2\"]",
        "aws_instance.metal_worker[\"metal-1\"]",
    ] {
        assert!(
            runbook.contains(contract),
            "the reviewed saved-plan runbook is missing: {contract}",
        );
    }
}

#[test]
fn production_cutover_runbook_orders_gates_and_fences_destructive_commands() {
    let runbook = read_workspace_file("docs/production-cutover-runbook.md");
    let ordered_stages = [
        "<!-- cutover-stage: 00-current-blocker -->",
        "<!-- cutover-stage: 10-maintenance-ingress-closed -->",
        "<!-- cutover-stage: 20-fresh-targets -->",
        "<!-- cutover-stage: 30-exact-release-credentials -->",
        "<!-- cutover-stage: 40-cordoned-nodes -->",
        "<!-- cutover-stage: 50-e12-empty-fleet -->",
        "<!-- cutover-stage: 60-e3-runtime-path -->",
        "<!-- cutover-stage: 70-final-gates -->",
        "<!-- cutover-stage: 80-reset-read-only -->",
        "<!-- cutover-stage: 90-reset-execute-forward-only -->",
        "<!-- cutover-stage: 100-uncordon-open -->",
    ];
    let mut prior = 0;
    for stage in ordered_stages {
        assert_eq!(
            runbook.matches(stage).count(),
            1,
            "cutover stage marker must be unique: {stage}"
        );
        let position = runbook.find(stage).expect("cutover stage marker");
        assert!(position >= prior, "cutover stage is out of order: {stage}");
        prior = position + stage.len();
    }

    for forbidden in [
        "rm -rf",
        "aws s3 rm",
        "kubectl delete namespace",
        "DROP DATABASE",
        "DROP SCHEMA",
        "terraform destroy",
    ] {
        assert!(
            !runbook.contains(forbidden),
            "runbook regained a broad destructive command: {forbidden}"
        );
    }

    let blocker = runbook
        .find("Current verdict: HOLD before destructive reset and public opening")
        .expect("top-level reset blocker");
    let boundary = runbook
        .find("<!-- forward-only-boundary: immutable-reset-started -->")
        .expect("forward-only boundary");
    let opening = runbook
        .find("<!-- cutover-stage: 100-uncordon-open -->")
        .expect("opening stage");
    assert!(blocker < boundary && boundary < opening);
    assert!(runbook[..boundary].contains("dry-run only"));
    assert!(runbook[boundary..opening].contains("there is no rollback/cancel path"));
    assert!(runbook[opening..].contains("DEFERRED(CROSS_COMPONENT_MUTATION_ADMISSION_OPEN)"));
}

#[test]
fn production_cutover_native_full_log_is_frozen_before_exact_job_publication() {
    let runbook = read_workspace_file("docs/production-cutover-runbook.md");
    assert!(
        !runbook.contains("/srv/cats-build/jobs/"),
        "the qualification runner stores immutable job outputs below /srv/cats-build/target"
    );

    let phase_zero = runbook
        .split_once("## 0. Freeze and qualify the exact release before the window")
        .and_then(|(_, remainder)| {
            remainder.split_once("<!-- cutover-stage: 10-maintenance-ingress-closed -->")
        })
        .map(|(section, _)| section)
        .expect("Stage A phase 0 release qualification section");
    let final_gates = runbook
        .split_once("## 8. Recheck final full and Linux gates")
        .and_then(|(_, remainder)| remainder.split_once("## Stage B"))
        .map(|(section, _)| section)
        .expect("Stage A final gates section");

    for (section, job_id) in [
        (phase_zero, "<QUALIFICATION_JOB_ID>"),
        (final_gates, "<FINAL_QUALIFICATION_JOB_ID>"),
    ] {
        let run = section.find("cats-run-build").expect("native full runner");
        let pipefail = section[run..]
            .find("set -o pipefail")
            .map(|position| run + position)
            .expect("native full pipefail gate");
        let log = section[pipefail..]
            .find("tee \"$CATS_BUILD_OUTPUT_DIR/quality-full.log\"")
            .map(|position| pipefail + position)
            .expect("native full frozen log writer");
        let publish = section[log..]
            .find("cats-publish-content-addressed evidence")
            .map(|position| log + position)
            .expect("native full evidence publisher");
        let expected_path = format!(
            "/srv/cats-build/target/<FINAL_RELEASE_SHA>-<SOURCE_MANIFEST_SHA256>-<SOURCE_BUNDLE_SHA256>/{job_id}/output/quality-full.log"
        );
        let exact_output = section[publish..]
            .find(&expected_path)
            .map(|position| publish + position)
            .expect("exact immutable job output path");

        assert!(run < pipefail && pipefail < log && log < publish && publish < exact_output);
    }
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
fn production_platform_preflight_requires_one_nat_gateway_per_az() {
    let checker = workspace_root().join("deploy/aws/terraform/check-platform-tfvars.sh");
    let guide = read_workspace_file("deploy/aws/terraform/README.md");
    let preflight = guide
        .find("../../check-platform-tfvars.sh platform.auto.tfvars")
        .expect("platform tfvars preflight in operator guide");
    let plan = guide
        .find("terraform plan -refresh-only -out=platform-refresh.tfplan")
        .expect("platform refresh-only plan in operator guide");
    assert!(
        preflight < plan,
        "the private production tfvars must be checked before Terraform reads them",
    );
    let fixture_dir = tempfile::tempdir().expect("temporary tfvars directory");
    let run = |name: &str, contents: &str| {
        let path = fixture_dir.path().join(name);
        std::fs::write(&path, contents).expect("write tfvars fixture");
        Command::new(&checker)
            .arg(&path)
            .output()
            .unwrap_or_else(|error| panic!("run {}: {error}", checker.display()))
    };

    let accepted = run(
        "accepted.tfvars",
        "availability_zone_count = 2\none_nat_gateway_per_az = true # deployed topology\n",
    );
    assert!(
        accepted.status.success(),
        "preflight rejected the safe production NAT setting: {}",
        String::from_utf8_lossy(&accepted.stderr),
    );

    for (name, contents) in [
        ("false.tfvars", "one_nat_gateway_per_az = false\n"),
        ("missing.tfvars", "availability_zone_count = 2\n"),
        (
            "duplicate.tfvars",
            "one_nat_gateway_per_az = true\none_nat_gateway_per_az = true\n",
        ),
        (
            "expression.tfvars",
            "one_nat_gateway_per_az = local.expected_nat_topology\n",
        ),
    ] {
        let rejected = run(name, contents);
        assert!(
            !rejected.status.success(),
            "preflight accepted unsafe or ambiguous fixture {name}",
        );
    }
}

#[test]
fn production_maintenance_is_one_reviewed_terraform_transition() {
    let stack_main =
        read_workspace_file("deploy/aws/terraform/stacks/production-application/main.tf");
    let stack_variables =
        read_workspace_file("deploy/aws/terraform/stacks/production-application/variables.tf");
    let module_main = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    let module_variables =
        read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/variables.tf");
    let example = read_workspace_file(
        "deploy/aws/terraform/stacks/production-application/production.tfvars.example",
    );

    let maintenance = stack_variables
        .split_once("variable \"maintenance_mode\"")
        .and_then(|(_, rest)| rest.split_once("\n}"))
        .map(|(section, _)| section)
        .expect("production maintenance_mode variable");
    assert!(maintenance.contains("default     = false"));
    let public_ingress = stack_variables
        .split_once("variable \"enable_public_ingress\"")
        .and_then(|(_, rest)| rest.split_once("\n}"))
        .map(|(section, _)| section)
        .expect("production enable_public_ingress variable");
    assert!(public_ingress.contains("default     = false"));
    let module_public_ingress = module_variables
        .split_once("variable \"enable_public_ingress\"")
        .and_then(|(_, rest)| rest.split_once("\n}"))
        .map(|(section, _)| section)
        .expect("Kubernetes module enable_public_ingress variable");
    assert!(module_public_ingress.contains("default     = false"));
    // Compare the token sequence, not the column: `terraform fmt` aligns `=`
    // to the longest key in the block, so any new module argument would
    // otherwise break these assertions without changing the wiring.
    for expected in [
        ["maintenance_mode", "=", "var.maintenance_mode"],
        ["enable_public_ingress", "=", "var.enable_public_ingress"],
    ] {
        assert!(
            stack_main
                .lines()
                .any(|line| line.split_whitespace().collect::<Vec<_>>() == expected),
            "production application maintenance wiring lost {expected:?}"
        );
    }
    let dns_gate =
        "var.route53_zone_id != null && var.enable_public_ingress && !var.maintenance_mode";
    assert!(
        stack_main.contains(dns_gate),
        "production application maintenance wiring lost {dns_gate:?}"
    );
    for expected in [
        "var.maintenance_mode ? 0 : var.control_plane_replicas",
        "var.enable_public_ingress && !var.maintenance_mode",
        "replicas = local.effective_control_plane_replicas",
        "min_available = var.maintenance_mode ? \"0\" : \"1\"",
        "suspend                       = var.maintenance_mode",
        "for_each = local.effective_public_ingress",
        "count = local.effective_public_ingress",
    ] {
        assert!(
            module_main.contains(expected),
            "Kubernetes maintenance boundary lost {expected:?}"
        );
    }
    assert!(example.contains("maintenance_mode = false"));
    assert!(example.contains("enable_public_ingress = false"));
}

#[test]
fn production_clean_slate_reset_contract_passes_offline_fixture() {
    let output = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/production-clean-slate-reset-fixture.py"))
        .output()
        .expect("run production clean-slate reset fixture");
    assert!(
        output.status.success(),
        "clean-slate reset fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("fixture output is UTF-8");
    assert!(stdout.contains("paginated versions+markers"));
    assert!(stdout.contains("fresh namespace preserved"));
    assert!(stdout.contains("post-green blocker passed"));
    assert!(stdout.contains("closed forward-resume"));
    assert!(stdout.contains("crash replay"));
    assert!(stdout.contains("mechanical prerequisite blocks"));
    assert!(stdout.contains("recoverable receipt publication"));
    assert!(stdout.contains("S3 expected-owner gates passed"));
    assert!(stdout.contains("fresh DB read-only"));
    assert!(stdout.contains("ingress Closed"));
    assert!(stdout.contains("post-open forward/credential-independent cleanup verification"));
}

/// The cutover tools refuse group- or world-writable ancestors. The Linux
/// gate's default /tmp is sticky, so scratch space moves under the
/// workspace target directory there; macOS's per-user /var/folders default
/// already satisfies the contract (and the workspace itself sits under the
/// group-writable /Users, so it cannot serve as the base).
fn contract_fixture_tmpdir() -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    {
        // Prefer the gate's target volume: the repository bind mount on a
        // macOS Docker host is virtiofs, which cannot re-resolve a replaced
        // inode through /proc/self/fd the way the held-descriptor races
        // require. The native build host relocates the cargo target outside
        // its read-only checkout via CARGO_TARGET_DIR; the workspace target
        // stays the last resort for writable checkouts.
        let base = std::env::var_os("CATS_LINUX_TARGET_DIRECTORY")
            .or_else(|| std::env::var_os("CARGO_TARGET_DIR"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| workspace_root().join("target"))
            .join("contract-fixture-tmp");
        std::fs::create_dir_all(&base).expect("create contract fixture tmpdir");
        base.canonicalize()
            .expect("canonicalize contract fixture tmpdir")
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::temp_dir()
    }
}

#[test]
fn production_cutover_proof_set_contract_passes_offline_fixture() {
    let output = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/production-cutover-proof-set-fixture.py"))
        .env("TMPDIR", contract_fixture_tmpdir())
        .output()
        .expect("run production cutover proof-set fixture");
    assert!(
        output.status.success(),
        "cutover proof-set fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn e3_operator_window_persistence_contract_passes_offline_fixture() {
    let output = Command::new("bash")
        .arg(
            workspace_root()
                .join("deploy/metal/tests/runtime-cutover-e3-window-persistence-fixture.sh"),
        )
        .arg(workspace_root().join("deploy/metal/runtime-cutover-e3-window.sh"))
        .env("TMPDIR", contract_fixture_tmpdir())
        .output()
        .expect("run E3 operator window persistence fixture");
    assert!(
        output.status.success(),
        "E3 window persistence fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("fixture output is UTF-8");
    assert!(stdout.contains("all cases passed"));
}

/// The operator-trust and installer fixtures sign with a real Ed25519-capable
/// openssl; macOS's LibreSSL lacks the algorithm, so probe the well-known
/// locations and fail (never skip) when none qualifies.
fn ed25519_openssl() -> String {
    for candidate in [
        "/usr/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
    ] {
        let Ok(output) = Command::new(candidate)
            .args(["list", "-public-key-algorithms"])
            .output()
        else {
            continue;
        };
        if output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .to_ascii_lowercase()
                .contains("ed25519")
        {
            return candidate.to_owned();
        }
    }
    panic!("no Ed25519-capable openssl found at the well-known locations");
}

#[test]
fn production_cutover_operator_trust_contract_passes_offline_fixture() {
    let output = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/production-cutover-operator-trust-fixture.py"))
        .arg("--tool")
        .arg(workspace_root().join("deploy/aws/production-cutover-operator-trust.py"))
        .arg("--openssl")
        .arg(ed25519_openssl())
        .env("TMPDIR", contract_fixture_tmpdir())
        .output()
        .expect("run production cutover operator trust fixture");
    assert!(
        output.status.success(),
        "operator trust fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn install_operator_tools_contract_passes_offline_fixture() {
    let output = Command::new("bash")
        .arg(workspace_root().join("deploy/aws/install-operator-tools-fixture.sh"))
        .arg("--openssl")
        .arg(ed25519_openssl())
        .env("TMPDIR", contract_fixture_tmpdir())
        .output()
        .expect("run install-operator-tools fixture");
    assert!(
        output.status.success(),
        "install-operator-tools fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn production_final_open_contract_passes_offline_fixture() {
    let output = Command::new("python3")
        .arg(workspace_root().join("deploy/aws/production-final-open-fixture.py"))
        .output()
        .expect("run production final-open fixture");
    assert!(
        output.status.success(),
        "production final-open fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("fixture output is UTF-8"),
        "production final-open fixture: PASS\n"
    );
}

#[test]
fn old_host_positive_stop_contract_passes_calibrated_offline_fixture() {
    let root = workspace_root();
    let output = Command::new("python3")
        .arg(root.join("deploy/aws/old-host-positive-stop-fixture.py"))
        .arg("--tool")
        .arg(root.join("deploy/aws/old-host-positive-stop.py"))
        .output()
        .expect("run old-Host positive-stop fixture");
    assert!(
        output.status.success(),
        "old-Host positive-stop fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("fixture output is UTF-8");
    for calibrated_boundary in [
        "calibrated runtime refusal",
        "descendant/PID-reuse",
        "absent/failed units",
        "ambiguous EC2 discovery/replay",
        "exact AWS identity/rules/ENIs/stable-deadline",
        "no-replace",
        "exact coverage",
    ] {
        assert!(
            stdout.contains(calibrated_boundary),
            "fixture omitted {calibrated_boundary:?}"
        );
    }

    let producer = read_workspace_file("deploy/aws/old-host-positive-stop.py");
    for required in [
        "cats.old-host-positive-stop-inventory.v1",
        "cgroup_v2_root",
        "\"--no-ask-password\", \"stop\"",
        "modify-network-interface-attribute",
        "host_fence_event\": \"not_established",
        "object_write_fence\": \"not_established",
        "production_reset_prerequisite\": \"proposed_unaccepted",
    ] {
        assert!(producer.contains(required), "producer lost {required:?}");
    }
    assert!(!producer.contains("shell=True"));
    assert!(!producer.contains("metering_cgroup_root"));

    let specification = read_workspace_file("docs/specs/old-host-positive-stop-v1.md");
    assert!(specification.contains("Status: **Proposed**"));
    assert!(specification.contains("cgroup_v2_root: canonical absolute cgroup2 mount root"));
    assert!(!specification.contains("metering_cgroup_root"));
    assert!(specification.contains("不是 ADR-0040 的 `HostFenceEvent`"));
    assert!(specification.contains("不能解除"));

    // The mechanical block is the fail-closed proof-set default: without the
    // explicit D7 operator attestation input, the positive-stop proof branch
    // raises before any destructive step.
    let reset = read_workspace_file("deploy/aws/production-clean-slate-reset.py");
    assert!(reset.contains("--accept-manual-fence-evidence"));
    assert!(reset.contains("local_positive_stop_verifier"));
    let proof_set = read_workspace_file("deploy/aws/production_cutover_proof_set.py");
    assert!(proof_set.contains("class _UnavailableLocalPositiveStopVerifier"));
    assert!(proof_set.contains("local positive-stop evidence remains Proposed with no accepted"));
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
fn production_fresh_schema_and_chunkstore_prefix_are_single_reviewed_inputs() {
    let reset_runbook = read_workspace_file("deploy/aws/production-clean-slate-reset.md");
    assert!(
        reset_runbook.contains("--fresh-chunkstore-prefix cats-fresh"),
        "the contract needs a non-default prefix to calibrate the former hardcoded-worker mismatch"
    );

    let infrastructure =
        read_workspace_file("deploy/aws/terraform/stacks/production-infrastructure/main.tf");
    assert_eq!(
        infrastructure.matches("= var.chunkstore_prefix").count(),
        3,
        "one reviewed infrastructure input must feed usage IAM, the fresh usage instance and the worker deployment"
    );
    assert!(infrastructure
        .lines()
        .any(|line| line.split_whitespace().collect::<Vec<_>>()
            == [
                "control_postgres_schema",
                "=",
                "var.control_postgres_schema"
            ]));

    let worker_variables =
        read_workspace_file("deploy/aws/terraform/modules/metal-worker-deployment/variables.tf");
    assert!(worker_variables.contains("variable \"chunkstore_prefix\""));
    assert!(worker_variables.contains("variable \"control_postgres_schema\""));
    assert_eq!(
        worker_variables
            .matches("\"CATS_CHUNKSTORE_PREFIX\"")
            .count(),
        2,
        "neither caller-owned environment map may replace the exact module input"
    );

    let worker_module =
        read_workspace_file("deploy/aws/terraform/modules/metal-worker-deployment/main.tf");
    assert_eq!(
        worker_module
            .matches("CATS_CHUNKSTORE_PREFIX=${var.chunkstore_prefix}")
            .count(),
        2,
        "both a fresh seed and an existing worker environment must receive the exact prefix"
    );
    assert_eq!(
        worker_module
            .matches("CATS_POSTGRES_SCHEMA=${var.control_postgres_schema}")
            .count(),
        2,
        "both a fresh seed and an existing worker environment must receive the exact schema"
    );

    let worker_unit = read_workspace_file("deploy/aws/metal/cats-worker.service");
    assert!(worker_unit.contains("--object-store-option prefix=${CATS_CHUNKSTORE_PREFIX}"));
    assert!(!worker_unit.contains("--object-store-option prefix=cats"));

    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    assert!(workflow.contains("CHUNKSTORE_PREFIX: ${{ vars.CHUNKSTORE_PREFIX }}"));
    assert!(workflow.contains("-var=\"chunkstore_prefix=$CHUNKSTORE_PREFIX\""));
    assert!(workflow.contains("CONTROL_POSTGRES_SCHEMA: ${{ vars.CONTROL_POSTGRES_SCHEMA }}"));
    assert!(workflow.contains("--schema \"CATS_POSTGRES_URL=$CONTROL_POSTGRES_SCHEMA\""));
    assert!(workflow.contains("-var=\"control_postgres_schema=$CONTROL_POSTGRES_SCHEMA\""));
    assert!(workflow.contains("${CONTROL_POSTGRES_SCHEMA}.control_schema_version"));

    for variables_path in [
        "deploy/aws/terraform/stacks/production-infrastructure/variables.tf",
        "deploy/aws/terraform/stacks/production-application/variables.tf",
    ] {
        let variables = read_workspace_file(variables_path);
        let prefix = variables
            .split_once("variable \"chunkstore_prefix\"")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(section, _)| section)
            .expect("production chunkstore_prefix variable");
        assert!(
            !prefix.contains("default"),
            "{variables_path} must require the reviewed prefix"
        );
        for canonical_guard in [
            "!startswith(var.chunkstore_prefix, \"/\")",
            "!endswith(var.chunkstore_prefix, \"/\")",
            "!strcontains(var.chunkstore_prefix, \"..\")",
            "!strcontains(var.chunkstore_prefix, \"//\")",
        ] {
            assert!(prefix.contains(canonical_guard));
        }

        let schema = variables
            .split_once("variable \"control_postgres_schema\"")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(section, _)| section)
            .expect("production control_postgres_schema variable");
        assert!(
            !schema.contains("default"),
            "{variables_path} must require the reviewed fresh schema"
        );
        assert!(schema.contains("^cats_[a-z0-9_]+$"));
    }

    let application =
        read_workspace_file("deploy/aws/terraform/stacks/production-application/main.tf");
    assert!(
        application
            .lines()
            .any(|line| line.split_whitespace().collect::<Vec<_>>()
                == ["chunkstore_prefix", "=", "var.chunkstore_prefix"]),
        "the production application stack must pass through the reviewed chunkstore prefix"
    );
    assert!(application
        .lines()
        .any(|line| line.split_whitespace().collect::<Vec<_>>()
            == [
                "control_postgres_schema",
                "=",
                "var.control_postgres_schema"
            ]));
    let kubernetes = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    assert!(kubernetes.contains("prefix=${var.chunkstore_prefix}"));
    assert!(kubernetes.contains("options=-csearch_path%3D${var.control_postgres_schema}"));

    let manual_environment = read_workspace_file("deploy/aws/metal/worker.env.example");
    assert!(manual_environment.contains("CATS_CHUNKSTORE_PREFIX=cats"));
    assert!(manual_environment.contains("CATS_POSTGRES_SCHEMA=cats_fresh"));
    let renderer = read_workspace_file("deploy/aws/metal/render-postgres-url.sh");
    assert!(renderer.contains("options=-csearch_path%3D${CATS_POSTGRES_SCHEMA}"));
    let worker_unit = read_workspace_file("deploy/aws/metal/cats-worker.service");
    assert!(worker_unit.contains("url-file=/run/cats/postgres-url"));
    let verifier = read_workspace_file("deploy/aws/tools/verify-manual-release.py");
    assert!(verifier.contains("\"cats-worker.service\""));
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
    // Split on the stage name, not the base image: the base moved to Amazon
    // ECR Public because the build host cannot reach Docker Hub.
    // COPY --chmod also stamps the parent directories it creates, which left
    // /opt/cats and /opt/cats/release unsearchable at 0644 and made the
    // startup filesystem contract unsatisfiable. The directories are created
    // with their exact mode first and the build asserts it.
    // cats-controld loads three installed artifacts at startup and refuses to
    // run without any of them. A deployment that mounts only some of them
    // crash-loops, which is how the production rollout failed, so the module
    // must mount every one.
    let kubernetes = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    for mount in [
        "/etc/cats/identity/runtime-provisioner-trust.v1.json",
        "/etc/cats/production-cutover-operator-trust.v1.json",
    ] {
        assert!(
            kubernetes.contains(&format!("mount_path = \"{mount}\"")),
            "control plane deployment must mount {mount}"
        );
    }

    assert!(dockerfile.contains("install -d -o 0 -g 0 -m 0755 /opt/cats /opt/cats/release"));
    assert!(dockerfile.contains(r#"test "$(stat -c %a /opt/cats)" = 755"#));

    let runtime = dockerfile
        .split_once(" AS runtime\n")
        .and_then(|(_, rest)| rest.split_once("FROM runtime AS credential-refresher"))
        .map(|(stage, _)| stage)
        .expect("dedicated control-plane runtime stage");
    assert!(runtime.contains("ENTRYPOINT [\"/usr/local/bin/cats-controld\"]"));

    assert!(!runtime.contains("cats-object-write-gatewayd"));
}

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
    assert!(probe.contains("SELECT current_schema()"));
    assert!(probe.contains("SELECT version FROM ${CONTROL_POSTGRES_SCHEMA}.control_schema_version"));
    assert!(probe.contains("$RUNNER_TEMP/proposed-control-postgres-url"));
    assert!(runner.contains("-v ON_ERROR_STOP=1"));
    assert!(runner.contains("create secret generic \"$runtime_secret\""));
    assert!(runner.contains("--from-file=\"CATS_POSTGRES_URL=$postgres_url_file\""));
    assert!(runner.contains("logs \"$probe\" --container=psql"));
    assert!(runner.contains("state.terminated.exitCode"));
    assert!(
        !runner
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .any(|line| line.contains("--attach")),
        "the schema probe must not attach to the short-lived container"
    );
    assert!(probe.contains("*'does not exist'*"));
    assert!(probe.contains("${CONTROL_POSTGRES_SCHEMA}.control_schema_version"));
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
        4,
        "build, Clippy, tests and rustdoc must share the isolated target root"
    );
    assert!(!linux_gate.contains("--target-dir /target"));
}

#[test]
fn linux_quality_gate_uses_disposable_postgres_without_weakening_native_full() {
    let quality = read_workspace_file("scripts/quality.sh");
    let linux_gate = read_workspace_file("scripts/linux-gate.sh");

    assert!(
        linux_gate.contains("--tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=2g"),
        "the Docker Linux compatibility gate should keep disposable PostgreSQL I/O in memory"
    );
    for setting in [
        "-c fsync=off",
        "-c synchronous_commit=off",
        "-c full_page_writes=off",
    ] {
        assert!(
            linux_gate.contains(setting),
            "the disposable Linux PostgreSQL fixture lost {setting:?}"
        );
        assert!(
            !quality.contains(setting),
            "the native full gate must retain PostgreSQL's default durability settings"
        );
    }
}

#[test]
fn github_ci_jobs_are_retired_and_production_deployment_is_manual_only() {
    assert!(
        !workspace_root().join(".github/workflows/ci.yml").exists(),
        "the retired Rust workspace and Terraform GitHub CI jobs must stay absent"
    );

    let deployment = read_workspace_file(".github/workflows/deploy-production.yml");
    assert!(!deployment.contains("workflow_run"));
    assert!(!deployment.contains("workflows: [\"CI\"]"));
    assert!(deployment.contains("workflow_dispatch:"));
    assert!(deployment.contains("RELEASE_SHA: ${{ github.sha }}"));
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
        "rm --force --volumes \"$id\"",
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
    let blockd_manifest = read_workspace_file("blockd/Cargo.toml");
    let node_manifest = read_workspace_file("node-agent/Cargo.toml");
    let (_, systemd_gate) = linux_gate
        .split_once("# ProvisionRootImage restart inventory must query a real system manager.")
        .expect("focused systemd gate boundary");

    assert!(
        blockd_manifest.contains("test-vhost-user-frontend = [\"vhost/vhost-user-frontend\"]"),
        "the cross-crate Linux frontend must enable the dependency feature it compiles"
    );
    assert!(
        node_manifest.contains(
            "cats-blockd = { workspace = true, features = [\"test-vhost-user-frontend\"] }"
        ),
        "the Node Linux E2E must opt into the closed blockd frontend harness"
    );

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
        "node-privileged.expected",
        "ch::tests::real_linux_",
        "real_linux_pending_tap_rejects_name_replacement_at_every_configuration_boundary",
        "real_linux_scoped_tap_is_published_and_exact_in_a_private_network_namespace",
        "LC_ALL=C sort -o \"$observed_node_privileged_inventory\"",
        "privileged Node test inventory was not the exact known positive",
        "timeout --signal=TERM --kill-after=30s 20m",
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
            "docker_cli capture 12600 exec \"$LINUX_SYSTEMD_GATE\" timeout --signal=TERM --kill-after=30s 20m cargo test -p cats-node-agent --lib --all-features --locked --target-dir \"$LINUX_TARGET_DIRECTORY\" ch::tests::real_linux_ -- --ignored --list"
        ),
        "the privileged Node inventory must bound both Docker and its in-container Cargo process"
    );
    assert!(
        focused_command.contains(
            "exec \"$LINUX_SYSTEMD_GATE\" timeout --signal=TERM --kill-after=30s 20m cargo test -p cats-node-agent --lib --all-features --locked --no-fail-fast --target-dir \"$LINUX_TARGET_DIRECTORY\" ch::tests::real_linux_ -- --ignored --test-threads=1 --nocapture"
        ),
        "the privileged gate must run only the calibrated ignored Node inventory"
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
  "rm --force")
    [[ "${3:-}" == --volumes ]] || exit 64
    id="${!#}"
    path="$(object_by_id container "$id")"
    name="${path#"$state/container."}"
    rm -f -- "$path"
    rm -f -- "$state/anonymous-volume.$name"
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
    if [[ "$name" == cats-linux-pg-* \
      && " $* " != *" --tmpfs /var/lib/postgresql/data:"* ]]; then
      : >"$state/anonymous-volume.$name"
      : >"$state/anonymous-volume-created.$name"
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
    if [[ "$mode" == workspace-stage-failure && "$name" == cats-linux-workspace-gate-* ]]; then
      printf '%s\n' '==> Linux quality stage failures: tests(exit=1)' >&2
      exit 1
    fi
    if [[ "$mode" == workspace-build-failure && "$name" == cats-linux-workspace-gate-* ]]; then
      printf '%s\n' '==> Linux quality stage failures: build(exit=101)' >&2
      exit 2
    fi
    ;;
  "exec "*)
    case "$*" in
      *" cat /proc/1/comm") printf 'systemd\n' ;;
      *" cat /proc/1/cgroup") printf '0::/init.scope\n' ;;
      *" systemctl is-system-running --quiet") ;;
      *" sh -ceu "*) ;;
      *" timeout --signal=TERM --kill-after=30s 20m cargo test "*" -- --ignored --list")
        : >"$state/focused-systemd-test-list-ran"
        if [[ "$mode" == timeout-systemd-test-list ]]; then
          exit 124
        fi
        if [[ "$mode" != zero-systemd-test ]]; then
          printf '%s\n' \
            'ch::tests::real_linux_pending_tap_rejects_name_replacement_at_every_configuration_boundary: test' \
            'ch::tests::real_linux_scoped_tap_is_published_and_exact_in_a_private_network_namespace: test'
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
                    || line == format!("rm --force --volumes {id}")
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
                format!(
                    "rm --force --volumes owned-cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}-id"
                ),
                format!(
                    "rm --force --volumes owned-cats-linux-pg-{LINUX_GATE_TEST_TOKEN}-id"
                ),
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
            workspace_started.elapsed() < cats_test_support::poll_bound(),
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

    let deadline = Instant::now() + cats_test_support::poll_bound();
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
            panic!("TERM cleanup exceeded the test poll bound");
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
        .find("rm --force --volumes late-workspace-id")
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
        format!("anonymous-volume.cats-linux-pg-{LINUX_GATE_TEST_TOKEN}"),
    ] {
        assert!(
            !state.join(&resource).exists(),
            "intended resource remained after response-loss settlement: {resource}"
        );
    }
    assert!(
        !state
            .join(format!(
                "anonymous-volume-created.cats-linux-pg-{LINUX_GATE_TEST_TOKEN}"
            ))
            .exists(),
        "the PostgreSQL tmpfs should override postgres:16's anonymous data volume"
    );

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
        .find("rm --force --volumes response-loss-workspace-id")
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
            && trace.contains(&format!("rm --force --volumes {systemd_id}")),
        "focused systemd container was not gracefully and exactly cleaned:\n{trace}"
    );
}

#[cfg(unix)]
#[test]
fn linux_quality_gate_collects_privileged_failures_after_a_workspace_stage_failure() {
    let fixture = tempfile::tempdir().expect("Linux gate collected workspace failure fixture");
    let fake_bin = fixture.path().join("bin");
    let state = fixture.path().join("state");
    std::fs::create_dir_all(&state).expect("create fake Docker state");
    install_linux_gate_fake_cli(&fake_bin);

    let output = linux_gate_command(&fake_bin, &state, "workspace-stage-failure")
        .output()
        .expect("run Linux gate collected workspace failure regression");
    assert!(
        !output.status.success(),
        "a collected workspace failure incorrectly passed the Linux gate"
    );
    for marker in ["focused-systemd-test-list-ran", "focused-systemd-test-ran"] {
        assert!(
            state.join(marker).exists(),
            "workspace failure skipped independent privileged evidence {marker}"
        );
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Linux quality stage failures: tests(exit=1)"));
    assert!(stderr.contains("Linux quality stage failed: workspace (exit 1)"));
}

#[cfg(unix)]
#[test]
fn linux_quality_gate_never_uses_artifacts_after_the_current_workspace_build_failed() {
    let fixture = tempfile::tempdir().expect("Linux gate failed-build fixture");
    let fake_bin = fixture.path().join("bin");
    let state = fixture.path().join("state");
    std::fs::create_dir_all(&state).expect("create fake Docker state");
    install_linux_gate_fake_cli(&fake_bin);

    let output = linux_gate_command(&fake_bin, &state, "workspace-build-failure")
        .output()
        .expect("run Linux gate failed-build regression");
    assert!(
        !output.status.success(),
        "a failed current-source build incorrectly passed the Linux gate"
    );
    for marker in ["focused-systemd-test-list-ran", "focused-systemd-test-ran"] {
        assert!(
            !state.join(marker).exists(),
            "failed current-source build exposed stale privileged artifact {marker}"
        );
    }
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
    assert!(
        state.join("focused-systemd-test-list-ran").exists(),
        "the zero-test regression did not exercise the bounded inventory probe"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("privileged Node test inventory was not the exact known positive"),
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
            && trace.contains(&format!("rm --force --volumes {systemd_id}")),
        "empty test-inventory failure did not clean the focused container exactly:\n{trace}"
    );
}

#[cfg(unix)]
#[test]
fn linux_quality_gate_cleans_exact_resources_when_focused_test_inventory_times_out() {
    let fixture = tempfile::tempdir().expect("Linux gate focused-test timeout fixture");
    let fake_bin = fixture.path().join("bin");
    let state = fixture.path().join("state");
    std::fs::create_dir_all(&state).expect("create fake Docker state");
    install_linux_gate_fake_cli(&fake_bin);

    let output = linux_gate_command(&fake_bin, &state, "timeout-systemd-test-list")
        .output()
        .expect("run Linux gate focused-test timeout regression");
    assert!(
        !output.status.success(),
        "a timed-out exact Rust test inventory incorrectly passed the Linux gate"
    );
    assert!(
        state.join("focused-systemd-test-list-ran").exists(),
        "the timeout regression did not exercise the bounded inventory probe"
    );
    assert!(
        !state.join("focused-systemd-test-ran").exists(),
        "the real focused command ran after its inventory probe timed out"
    );
    for resource in [
        format!("network.cats-linux-net-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-pg-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}"),
        format!("container.cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN}"),
    ] {
        assert!(
            !state.join(&resource).exists(),
            "intended resource remained after focused test-inventory timeout: {resource}"
        );
    }
    let trace = std::fs::read_to_string(state.join("trace")).expect("fake Docker trace");
    let bounded_list = format!(
        "exec cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN} timeout --signal=TERM --kill-after=30s 20m cargo test -p cats-node-agent --lib --all-features --locked"
    );
    assert!(
        trace.contains(&bounded_list) && trace.contains("-- --ignored --list"),
        "the timeout regression did not preserve the in-container Cargo deadline:\n{trace}"
    );
    let systemd_id = format!("owned-cats-linux-systemd-gate-{LINUX_GATE_TEST_TOKEN}-id");
    assert!(
        trace.contains(&format!("stop --time 20 {systemd_id}"))
            && trace.contains(&format!("rm --force --volumes {systemd_id}")),
        "test-inventory timeout did not clean the focused container exactly:\n{trace}"
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

    let start_deadline = Instant::now() + cats_test_support::poll_bound();
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
        if signal_at.elapsed() >= cats_test_support::poll_bound() {
            child.kill().expect("kill timed-out Linux quality gate");
            child.wait().expect("reap timed-out Linux quality gate");
            panic!("start cancellation and exact cleanup exceeded the test poll bound");
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
            "rm --force --volumes owned-cats-linux-workspace-gate-{LINUX_GATE_TEST_TOKEN}-id"
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
            workspace_started.elapsed() < cats_test_support::poll_bound(),
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

    let deadline = signal_at + cats_test_support::poll_bound();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll Linux quality gate") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out Linux quality gate");
            child.wait().expect("reap timed-out Linux quality gate");
            panic!("hung cleanup exceeded the test poll bound");
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
    assert!(
        captured.contains("args=test --workspace --locked --no-fail-fast -- --test-threads=4\n")
    );
}

#[test]
fn quality_gates_collect_all_nonredundant_stage_failures() {
    let quality = read_workspace_file("scripts/quality.sh");
    let linux = read_workspace_file("scripts/linux-gate.sh");

    let fast = quality
        .split_once("run_fast() {")
        .and_then(|(_, rest)| rest.split_once("\n}"))
        .map(|(body, _)| body)
        .expect("fast quality gate");
    let full = quality
        .split_once("run_full() {")
        .and_then(|(_, rest)| rest.split_once("\n}"))
        .map(|(body, _)| body)
        .expect("full quality gate");

    assert!(quality.contains("run_collected_gates \\\n"));
    for stage in [
        "fmt run_fmt",
        "skills run_skills",
        "release-images run_release_images",
        "dependencies run_deps",
        "build run_build",
        "clippy run_clippy",
        "tests run_test",
        "rustdoc run_doc",
    ] {
        assert!(
            quality.contains(stage),
            "full gate lost collected stage {stage}"
        );
    }
    assert!(quality.contains("QUALITY_FAILURES+=("));
    assert!(quality.contains("quality stage failures"));
    assert!(quality.contains("cargo test --workspace --locked --no-fail-fast"));
    assert!(quality.contains("check) run_check ;;"));
    assert!(!fast.contains("check run_check"));
    assert!(!full.contains("check run_check"));
    assert!(quality.contains("quality stage passed: $label (${elapsed_seconds}s)"));

    assert!(!linux.contains("run_linux_stage check cargo check"));
    assert!(linux.contains("cargo clippy --workspace --all-targets"));
    assert!(linux.contains("--locked --keep-going --target-dir"));
    assert!(linux.contains("run_linux_stage tests cargo test"));
    assert!(linux.contains("--locked --no-fail-fast --target-dir"));
    assert!(linux.contains("Linux quality stage passed: $stage_name (${stage_elapsed_seconds}s)"));
    assert!(linux.contains("Linux quality stage failures:"));
    assert!(linux.contains("collect_gate_failure workspace"));
    assert!(linux.contains("collect_gate_failure node-privileged-inventory"));
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
    let trimmed_lines = terraform.lines().map(str::trim).collect::<Vec<_>>();
    assert!(
        trimmed_lines.windows(2).any(|pair| {
            pair == [
                "\"--control-store-url-file\",",
                "\"/etc/cats/runtime/CATS_POSTGRES_URL\",",
            ]
        }),
        "the production control Store must read its rotating DSN from the mounted file"
    );
    for expected in [
        "CATS_USAGE_POSTGRES_URL_FILE",
        "mount_path = \"/etc/cats/runtime\"",
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
          "CATS_POSTGRES_URL": "postgresql://cats:old@direct.example:5432/cats?sslmode=verify-full&options=-csearch_path%3Dcats_old",
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
            "--schema",
            "CATS_POSTGRES_URL=cats_fresh_cutover",
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
        "postgresql://cats:n%40w%3Ap%2Fss@cats-production-proxy.proxy.example:5432/cats?sslmode=verify-full&options=-csearch_path%3Dcats_fresh_cutover"
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
            "--schema",
            "CATS_POSTGRES_URL=cats_fresh_cutover",
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
        "replicas = local.effective_control_plane_replicas",
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
    assert!(terraform.contains("min_available = var.maintenance_mode ? \"0\" : \"1\""));
    assert!(
        !deployment.contains("type = \"Recreate\""),
        "Recreate deliberately creates a total control-plane outage"
    );
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

    // `checkpoints` leads the list because the kernel-NBD pool proof snapshots
    // it: an absent namespace is unprovable, not empty, so a Node without it can
    // never attest.
    let provisioned_state_namespaces =
        "checkpoints vmm-socket-receipts vmm-launch-v1 blockd-socket-intents-v1";

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

    // The production deployment is the terraform association, not either
    // bootstrap script. Checking only the bootstraps let the association ship
    // without the provisioner at all: the Agent then failed every start on the
    // runtime socket root it opens and never creates.
    for bootstrap in [
        "deploy/aws/metal/install-worker.sh",
        "deploy/metal/install.sh",
        "deploy/aws/terraform/modules/metal-worker-deployment/main.tf",
    ] {
        let source = read_workspace_file(bootstrap);
        let install = source
            .find("/usr/lib/tmpfiles.d/cats-vmm.conf")
            .unwrap_or_else(|| panic!("{bootstrap} does not install runtime tmpfiles"));
        let provision = source
            .find("\"$PREFIX/bin/provision-vmm-socket-namespaces\"")
            .or_else(|| source.find("\"$CATS_PREFIX/bin/provision-vmm-socket-namespaces\""))
            .or_else(|| {
                source.find("\"${var.install_root}/bin/provision-vmm-socket-namespaces\"\n")
            })
            .unwrap_or_else(|| panic!("{bootstrap} does not run the runtime provisioner"));
        assert!(
            install < provision,
            "{bootstrap} must install tmpfiles before provisioning runtime roots"
        );
    }

    // The association can only install what the worker artifact carries.
    let worker_artifact = read_workspace_file("deploy/aws/Dockerfile.worker-artifact");
    for member in [
        "deploy/aws/metal/provision-vmm-socket-namespaces.sh",
        "deploy/metal/tmpfiles/cats-vmm.conf",
    ] {
        assert!(
            worker_artifact.contains(member),
            "the worker artifact must carry {member}, or the deployment cannot provision \
             the runtime roots the Agent opens"
        );
    }
}

#[test]
fn release_artifacts_share_one_canonical_guest_payload() {
    let receipt_argument =
        "--guest-runtime-profile-receipt-file /opt/cats/release/guest-runtime-profile.v1.json";
    let unit = "deploy/metal/systemd/cats-controld.service";
    let source = read_workspace_file(unit);
    assert!(
        source.contains(receipt_argument),
        "{unit} lost the exact installed release receipt"
    );

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
    for release_binding in [
        "ARG CATS_RELEASE_COMMIT_SHA",
        "ENV CATS_RELEASE_COMMIT_SHA=${CATS_RELEASE_COMMIT_SHA}",
        "grep -Eq '^[0-9a-f]{40}$'",
    ] {
        assert!(
            control_image.contains(release_binding),
            "Control image lost qualified source binding {release_binding:?}"
        );
    }
    let worker_image = read_workspace_file("deploy/aws/Dockerfile.worker-artifact");
    assert!(worker_image.contains("COPY guest-runtime-release.v1 /guest-runtime-release.v1"));
    assert!(worker_image.contains(
        "COPY --from=builder --chmod=0755 /out/old-host-positive-stop.py /old-host-positive-stop.py"
    ));

    // cats-worker.service requires /opt/cats/bin/setup-guest-network before
    // start; the bundle must carry it and the bundle-driven installer must
    // install it, or a bundle-deployed worker can never start its unit.
    let worker_unit = read_workspace_file("deploy/aws/metal/cats-worker.service");
    assert!(worker_unit.contains("ExecStartPre=/opt/cats/bin/setup-guest-network"));
    assert!(worker_image.contains(
        "COPY --from=builder --chmod=0755 /out/setup-guest-network.sh /setup-guest-network.sh"
    ));
    let worker_module =
        read_workspace_file("deploy/aws/terraform/modules/metal-worker-deployment/main.tf");
    assert!(worker_module.contains(
        "install -D -m 0755 \"$stage_path/setup-guest-network.sh\" \"${var.install_root}/bin/setup-guest-network\""
    ));
    for release_binding in [
        "ARG CATS_RELEASE_COMMIT_SHA",
        "ENV CATS_RELEASE_COMMIT_SHA=${CATS_RELEASE_COMMIT_SHA}",
        "grep -Eq '^[0-9a-f]{40}$'",
    ] {
        assert!(
            worker_image.contains(release_binding),
            "worker image lost qualified source binding {release_binding:?}"
        );
    }
    let workflow = read_workspace_file(".github/workflows/release.yml");
    assert_eq!(
        workflow.matches("guest-runtime-release:\n").count(),
        1,
        "the workflow must have one Guest release producer"
    );
    assert!(workflow.contains("RELEASE_OUT=\"$PWD/guest-runtime-release.v1\""));
    let control = workflow
        .split_once("  control-plane-image:\n")
        .and_then(|(_, rest)| rest.split_once("  gateway-image:\n"))
        .map(|(section, _)| section)
        .expect("control-plane image job");
    let gateway = workflow
        .split_once("  gateway-image:\n")
        .and_then(|(_, rest)| rest.split_once("  worker-bundle:\n"))
        .map(|(section, _)| section)
        .expect("gateway image job");
    let worker = workflow
        .split_once("  worker-bundle:\n")
        .map(|(_, section)| section)
        .expect("worker bundle job");
    for consumer in [control, worker] {
        assert!(
            consumer.contains("needs: [aws-target, guest-runtime-release]"),
            "Control and Node artifacts must consume the canonical Guest release after the AWS target fence"
        );
        assert!(consumer.contains("uses: actions/download-artifact@v4"));
        assert!(consumer.contains("name: guest-runtime-release-v1"));
    }
    assert!(
        !gateway.contains("guest-runtime-release-v1"),
        "the Gateway image must not pretend to consume the shared Guest release artifact"
    );
    assert!(workflow.contains("build-args: CATS_RELEASE_COMMIT_SHA=${{ github.sha }}"));
    assert_eq!(
        workflow.matches("name: guest-runtime-release-v1").count(),
        3,
        "one upload and exactly two consumers must name the same artifact"
    );
    let production_workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    assert!(
        production_workflow.contains("build-args: CATS_RELEASE_COMMIT_SHA=${{ env.RELEASE_SHA }}")
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
fn manual_release_builder_verifies_all_final_artifacts_and_writes_one_receipt() {
    let root = workspace_root();
    let builder = read_workspace_file("deploy/aws/tools/build-manual-release.sh");
    for required in [
        "manual release builds require a clean checkout",
        "git archive --format=tar \"$source_sha\"",
        "rustup target add x86_64-unknown-linux-musl",
        "RELEASE_OUT=\"$guest_release\"",
        "--file deploy/aws/Dockerfile.control-plane",
        "--file deploy/aws/Dockerfile.gateway",
        "--build-arg \"CATS_RELEASE_COMMIT_SHA=$source_sha\"",
        "--file deploy/aws/Dockerfile.worker-artifact",
        "docker create --platform linux/amd64 \"$control_image_id\"",
        "docker create --platform linux/amd64 \"$gateway_image_id\"",
        "verify-manual-release.py",
        "--control-image-registry-verified false",
        "--control-image-registry-verified true",
        "--gateway-image-registry-verified false",
        "--gateway-image-registry-verified true",
        "--input-file \"guest_host_kernel=$guest_kernel\"",
        "--input-file \"old_host_positive_stop=$source_root/deploy/aws/old-host-positive-stop.py\"",
        "--input-file \"production_mutation_admission_operator=$source_root/deploy/aws/production-mutation-admission.py\"",
        "--input-file \"production_cutover_proof_set=$source_root/deploy/aws/production_cutover_proof_set.py\"",
        "--export-images",
        "type=oci,dest=$control_archive",
        "type=oci,dest=$gateway_archive",
        // Docker loads only its own archive format unless the daemon runs the
        // containerd image store, so the export must also produce the archives
        // the local identity checks and binary extraction load.
        "type=docker,dest=$control_load_archive",
        "type=docker,dest=$gateway_load_archive",
        "docker image load --input \"$control_load_archive\"",
        "docker image load --input \"$gateway_load_archive\"",
        // Those copies are build scratch and must never reach the handoff.
        "rm -f -- \"$control_load_archive\" \"$gateway_load_archive\"",
        // Cargo publishes a release binary as a hard link to its deps
        // artifact, so the verifier's single-link rule needs a private copy.
        "cp \"$guest_agent_bin\" \"$guest_agent_fingerprint\"",
        "--input-file \"guest_agent_binary=$guest_agent_fingerprint\"",
        // A failed release build must leave its partial tree for diagnosis
        // under a name that cannot be mistaken for a release.
        "incomplete release retained for diagnosis",
        "cats-control-plane-image.tar",
        "cats-gateway-image.tar",
        "> SHA256SUMS",
    ] {
        assert!(
            builder.contains(required),
            "manual release builder lost {required:?}"
        );
    }
    assert_eq!(
        builder.matches("RELEASE_OUT=\"$guest_release\"").count(),
        1,
        "the manual builder must run the Guest release generator exactly once"
    );
    assert!(
        !builder.contains("kubectl") && !builder.contains("terraform apply"),
        "artifact construction must not contain a deployment path"
    );
    assert!(
        builder.find("--control-image-registry-verified false")
            < builder.find("docker push \"$image_reference\""),
        "all local artifacts must pass the verifier before an optional registry push"
    );

    let output = Command::new("python3")
        .arg(root.join("deploy/aws/tools/manual-release-fixture.py"))
        .arg("--verifier")
        .arg(root.join("deploy/aws/tools/verify-manual-release.py"))
        .output()
        .expect("run manual release verifier fixture");
    assert!(
        output.status.success(),
        "manual release verifier fixture failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("fixture passed"));

    let publisher = read_workspace_file("deploy/aws/tools/publish-manual-release.sh");
    for required in [
        "--manifest-sha256",
        "verify-image-transport.py",
        "verify-manual-release.py",
        "registry-candidate",
        "docker image load --input",
        "docker buildx imagetools inspect --raw",
    ] {
        assert!(
            publisher.contains(required),
            "manual release publisher lost {required:?}"
        );
    }
    for forbidden in [
        "docker build ",
        "docker buildx build",
        "terraform",
        "kubectl",
    ] {
        assert!(
            !publisher.contains(forbidden),
            "manual release publisher gained rebuild/deployment effect {forbidden:?}"
        );
    }
}

#[test]
fn production_deployment_builds_the_same_guest_payload_as_release() {
    let release = read_workspace_file(".github/workflows/release.yml");
    let production = read_workspace_file(".github/workflows/deploy-production.yml");
    assert_eq!(
        production
            .matches("      - name: Build the one Guest payload\n")
            .count(),
        1,
        "the production deployment must build the Guest payload exactly once"
    );
    let payload_build = production
        .find("      - name: Build the one Guest payload\n")
        .expect("production Guest payload build");
    let image_build = production
        .find("      - name: Build and push control-plane image\n")
        .expect("production control-plane image build");
    assert!(
        payload_build < image_build,
        "the Guest payload must exist before Docker consumes it",
    );
    let step = |workflow: &str| {
        workflow
            .split_once("      - name: Build the one Guest payload\n")
            .and_then(|(_, rest)| rest.split_once("\n      - "))
            .map(|(body, _)| body.trim_end().to_owned())
            .expect("Guest runtime payload build step")
    };

    assert_eq!(
        step(&production),
        step(&release),
        "production and release workflows must build the exact same Guest runtime payload before the control-plane Docker build",
    );
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
    let deployment_lock = terraform
        .find("cats_acquire_worker_deployment_lock")
        .expect("Host deployment lock");
    let locked_cgroup = terraform[deployment_lock..]
        .find("cgroup_v2_root=\"$(cats_worker_cgroup_v2_root)\"")
        .map(|offset| deployment_lock + offset)
        .expect("cgroup-v2 root recomputation under the Host lock");
    let locked_idle_guard = terraform[locked_cgroup..]
        .find("require-idle-worker.sh\"")
        .map(|offset| locked_cgroup + offset)
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
        identity_validate < deployment_lock
            && deployment_lock < locked_cgroup
            && locked_cgroup < locked_idle_guard
            && locked_idle_guard < stop
            && stop < prepare
            && prepare < first_install
    );
    let pre_lock = &terraform[..deployment_lock];
    assert!(
        !pre_lock.contains("systemctl show"),
        "the deployment lock must be held before any systemctl query"
    );
    assert!(
        !pre_lock.contains("require-idle-worker.sh"),
        "the worker deployment must not reintroduce an unlocked idle guard before the Host lock"
    );
    assert!(
        !terraform.contains("--node-id"),
        "Terraform regained a CLI-derived Node identity"
    );
    for required in [
        "jq -er '.node_id' /etc/cats/identity/node-identity.v1.json",
        "[ \"$identity_instance\" = \"$instance_id\" ]",
        "[ \"$identity_region\" = \"$node_region\" ]",
        "CATS_NODE_ID=$node_id",
        "CATS_NODE_CONTROL_ENDPOINT=http://$private_ip:7301",
    ] {
        assert!(
            terraform.contains(required),
            "direct Node registration lost its closed identity/IMDS cross-check {required:?}"
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
