use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::io::Write;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
    let linux_gate = quality
        .split("run_linux() {")
        .nth(1)
        .and_then(|rest| rest.split("case \"${1:-full}\"").next())
        .expect("Linux quality-gate function");

    assert!(
        linux_gate.contains("apt-get install -qy --no-install-recommends e2fsprogs jq"),
        "the Linux gate must install jq before deployment probe fixtures execute"
    );
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
        "termination_grace_period_seconds = local.control_plane_termination_grace_period_seconds",
        "pre_stop {",
        "command = [\"/bin/sh\", \"-c\", \"sleep ${local.control_plane_pre_stop_delay_seconds}\"]",
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
        "control_plane_pre_stop_delay_seconds           = 15",
        "control_plane_termination_grace_period_seconds = 30",
        "condition     = local.control_plane_pre_stop_delay_seconds < local.control_plane_termination_grace_period_seconds",
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
fn production_ha_drill_deletes_only_the_elected_reconciler_under_a_guard() {
    let workflow = read_workspace_file(".github/workflows/verify-control-plane-ha.yml");
    let harness = read_workspace_file("test-results/qualification-20260805/ha-handoff.sh");
    let admin_adapter =
        read_workspace_file("test-results/qualification-20260805/live-hooks/q124-admin-node");
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
        "LOCK_Q124_LIFECYCLE",
        "ws_788c5bfc3931",
        "activeDeadlineSeconds: 300",
        "FOR UPDATE OF c",
        "PERFORM pg_sleep(90)",
        "CATS_HA_EXACT_OPERATION_CONVERGED",
        "reconciler leadership changed before the disruption boundary",
        ".metadata.deletionTimestamp == null",
        ".status.phase == \"Running\"",
        "https://cats.run/healthz",
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
        "both destructive and post-disruption steps must require disrupt mode"
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
    let lifecycle_lock = workflow
        .find("Lifecycle coordinator locked token=")
        .expect("coordinator proves the lifecycle row lock before disruption");
    let uid_preconditioned_eviction = workflow
        .find("deploy/aws/evict-pod-with-uid.sh cats \"$target\" \"$target_uid\"")
        .expect("workflow uses a PDB-aware UID-preconditioned eviction");
    let final_owner_resolution = workflow[..uid_preconditioned_eviction]
        .rfind("deploy/aws/select-reconciler-owner.sh")
        .expect("workflow re-resolves the elected owner at the final boundary");
    assert!(
        lifecycle_lock < final_owner_resolution
            && final_owner_resolution < uid_preconditioned_eviction,
        "the final owner must be resolved after the optional lifecycle lock and immediately before eviction"
    );
    for expected in [
        "CATS_SUT_WORKSPACE_ID must be exactly ws_788c5bfc3931",
        "CATS_TEST_WORKSPACE must be exactly default/qual-124-20260805",
        "verify_admin_hook_provenance",
        "-f mode=disrupt",
    ] {
        assert!(
            harness.contains(expected),
            "HA harness is missing {expected:?}"
        );
    }
    for expected in [
        "case \"${ACTION}\" in get|cats|cordon|uncordon)",
        "Node assignment escaped exact q124 scope",
        "/etc/cats/qualification-124/admin-token",
        "ws_788c5bfc3931",
    ] {
        assert!(
            admin_adapter.contains(expected),
            "q124 admin adapter is missing {expected:?}"
        );
    }
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
        ".change.after.spec[0].replicas >= 2",
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
