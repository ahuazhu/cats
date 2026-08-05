use std::path::{Path, PathBuf};
use std::process::Command;

const SCHEMA_PATH: &str = "control-plane/src/store/schema.rs";
const SCHEMA_VERSION_PATTERN: &str = r"s/^(pub\(super\)[[:space:]]+)?const[[:space:]]+SCHEMA_VERSION:[[:space:]]+i64[[:space:]]+=[[:space:]]+([0-9]+);$/\2/p";
const OLDEST_MIGRATABLE_PATTERN: &str = r"s/^(pub\(super\)[[:space:]]+)?const[[:space:]]+OLDEST_MIGRATABLE_SCHEMA_VERSION:[[:space:]]+i64[[:space:]]+=[[:space:]]+([0-9]+);$/\2/p";

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
fn production_deploy_extracts_versions_from_the_current_store_schema() {
    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    assert_eq!(
        workflow.matches(SCHEMA_PATH).count(),
        2,
        "production deployment must read both schema bounds from {SCHEMA_PATH}"
    );
    assert!(
        !workflow.contains("control-plane/src/store.rs"),
        "production deployment still refers to the pre-refactor Store module"
    );

    for (name, pattern) in [
        ("SCHEMA_VERSION", SCHEMA_VERSION_PATTERN),
        (
            "OLDEST_MIGRATABLE_SCHEMA_VERSION",
            OLDEST_MIGRATABLE_PATTERN,
        ),
    ] {
        assert!(
            workflow.contains(pattern),
            "production deployment does not use the tested {name} extraction pattern"
        );
        let output = Command::new("sed")
            .args(["-nE", pattern])
            .arg(workspace_root().join(SCHEMA_PATH))
            .output()
            .unwrap_or_else(|error| panic!("run sed for {name}: {error}"));
        assert!(output.status.success(), "sed failed for {name}");
        let value = String::from_utf8(output.stdout).expect("schema version is UTF-8");
        assert!(
            value.trim().parse::<i64>().is_ok(),
            "{name} did not yield one numeric value: {value:?}"
        );
    }
}

#[test]
fn production_schema_probe_fails_closed() {
    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    let probe = workflow
        .split("# The control store lives in PostgreSQL.")
        .nth(1)
        .and_then(|rest| rest.split("- name: Initialize application state").next())
        .expect("control schema probe block");

    assert!(probe.contains("query_status=$?"));
    assert!(probe.contains("-v ON_ERROR_STOP=1"));
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
fn production_database_clients_read_the_rotating_secret_files() {
    let terraform = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    for expected in [
        "--control-store-url-file",
        "url-file=/etc/cats/runtime/CATS_POSTGRES_URL",
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
fn production_deploy_detaches_the_legacy_control_volume_after_plan_and_before_apply() {
    let workflow = read_workspace_file(".github/workflows/deploy-production.yml");
    let plan = workflow
        .find("- name: Plan production deployment")
        .expect("production plan step");
    let detach = workflow
        .find("- name: Detach legacy control volume")
        .expect("legacy control-volume detach step");
    let apply = workflow
        .find("- name: Apply reviewed plan")
        .expect("production apply step");

    assert!(
        plan < detach && detach < apply,
        "the legacy volume must be detached only after the saved plan and before its apply"
    );

    let detach_step = workflow[detach..apply].to_owned();
    for expected in [
        "get namespace \"$namespace\" --output=name",
        "get pvc \"$legacy_claim\" --ignore-not-found --output=name",
        "show -json \"$RUNNER_TEMP/production.tfplan\"",
        "module.cats_kubernetes.kubernetes_deployment_v1.control_plane",
        "persistentVolumeClaim.claimName == $claim",
        "scale deployment \"$control_deployment\" --replicas=0",
        "remaining_consumers=\"$(control_volume_consumers)\"",
    ] {
        assert!(
            detach_step.contains(expected),
            "legacy detach step is missing {expected:?}"
        );
    }
    let attached_check = detach_step
        .find("if [[ -z \"$attached_consumers\" ]]")
        .expect("already-detached fast path");
    let plan_guard = detach_step
        .find("show -json \"$RUNNER_TEMP/production.tfplan\"")
        .expect("saved-plan replica guard");
    let scale = detach_step
        .find("scale deployment \"$control_deployment\" --replicas=0")
        .expect("legacy Deployment scale");
    assert!(
        attached_check < plan_guard && plan_guard < scale,
        "an unused PVC needs no scale, while a scale requires the saved-plan guard"
    );
    assert!(
        !detach_step.contains("finalizers") && !detach_step.contains("delete pvc"),
        "the deploy must release the mounted claim, never bypass PVC protection"
    );
}
