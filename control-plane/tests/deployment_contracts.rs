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
