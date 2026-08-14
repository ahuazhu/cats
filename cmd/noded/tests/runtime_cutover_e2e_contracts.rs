use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CASES: [&str; 9] = [
    "control-startup-schema",
    "node-registration-full-inventory",
    "cat-create-running",
    "durable-write-flush",
    "route-http-ws",
    "agent-restart-adoption",
    "volume-init-matrix",
    "usage-final-terminal-receipt",
    "delete-cleanup",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn git_head(root: &Path) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .expect("read fixture HEAD");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("HEAD is UTF-8")
        .trim()
        .to_owned()
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    exact_commit: String,
    build_receipt: PathBuf,
    release_manifest: PathBuf,
    binary: PathBuf,
    config: PathBuf,
    timeout: PathBuf,
    trace: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = workspace_root();
        let exact_commit = git_head(&root);
        let temp = tempfile::tempdir().expect("runtime cutover fixture");
        let build_receipt = temp.path().join("build-receipt.json");
        let release_manifest = temp.path().join("release-manifest.json");
        let binary = temp.path().join("cats-noded");
        let config = temp.path().join("cats-public.conf");
        let timeout = temp.path().join("timeout");
        let trace = temp.path().join("trace");

        fs::write(
            &build_receipt,
            format!(
                "{{\"exit_status\":0,\"output_frozen\":true,\"source_sha\":\"{exact_commit}\"}}\n"
            ),
        )
        .expect("write build receipt");
        fs::write(
            &release_manifest,
            format!("{{\"source\":{{\"commit\":\"{exact_commit}\"}},\"version\":1}}\n"),
        )
        .expect("write release manifest");
        fs::write(&binary, "fixture binary\n").expect("write binary fixture");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))
            .expect("make binary fixture executable");
        fs::write(&config, "public_setting=true\n").expect("write config fixture");
        fs::write(
            &timeout,
            r#"#!/usr/bin/env bash
set -euo pipefail
while [[ $1 == --* ]]; do
  case "$1" in
    --signal=*|--kill-after=*) shift ;;
    *) exit 64 ;;
  esac
done
shift
exec "$@"
"#,
        )
        .expect("write timeout fixture");
        fs::set_permissions(&timeout, fs::Permissions::from_mode(0o755))
            .expect("make timeout fixture executable");

        Self {
            _temp: temp,
            root,
            exact_commit,
            build_receipt,
            release_manifest,
            binary,
            config,
            timeout,
            trace,
        }
    }

    fn output_dir(&self, name: &str) -> PathBuf {
        self._temp.path().join(name)
    }

    fn run(
        &self,
        output_dir: &Path,
        block_path: &str,
        configure: impl FnOnce(&mut Command),
    ) -> Output {
        self.run_with_binary_digest(output_dir, block_path, &sha256(&self.binary), configure)
    }

    fn run_with_binary_digest(
        &self,
        output_dir: &Path,
        block_path: &str,
        binary_digest: &str,
        configure: impl FnOnce(&mut Command),
    ) -> Output {
        let mut command = Command::new("bash");
        command
            .arg(self.root.join("deploy/metal/runtime-cutover-e2e.sh"))
            .args(["--exact-commit", &self.exact_commit])
            .args(["--block-path", block_path])
            .args(["--run-id", "fixture-run"])
            .arg("--output-dir")
            .arg(output_dir)
            .arg("--build-receipt")
            .arg(&self.build_receipt)
            .arg("--release-manifest")
            .arg(&self.release_manifest)
            .args(["--guest-kernel", "fixture-guest-kernel"])
            .arg("--binary")
            .arg(format!(
                "noded={}@sha256:{}",
                self.binary.display(),
                binary_digest
            ))
            .arg("--config")
            .arg(format!("public={}", self.config.display()))
            .args([
                "--key-fingerprint",
                "route=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ])
            .arg("--scenario-driver")
            .arg(
                self.root
                    .join("deploy/metal/tests/runtime-cutover-e2e-scenario-fixture.sh"),
            )
            .env("CATS_E3_FIXTURE_MODE", "enabled")
            .env("CATS_E3_FIXTURE_TRACE", &self.trace)
            .env("CATS_E3_TIMEOUT_BIN", &self.timeout)
            .current_dir(&self.root);
        configure(&mut command);
        command.output().expect("run runtime cutover fixture")
    }

    fn run_v2_driver(&self, output_dir: &Path) -> Output {
        let fake = r#"#!/usr/bin/env bash
set -euo pipefail
role=$(basename "$0")
case "$role" in
  cats)
    [[ -n ${CATS_TOKEN:-} ]] || exit 65
    case " $* " in
      *" admin fleet-verify "*)
        printf '{"version":1,"release_commit_sha":"%s","snapshot":{"desired_runtime_count":0,"current_runtime_observation_count":0,"nodes":[{"node_id":"node_fixture","inventory":{"complete_inventory":true,"assigned_desired_count":0,"runtime_count":0,"residue_count":0,"lifecycle_open_count":0,"route_active_count":0,"route_closed_count":0,"active_guard_count":0,"cancellation_pending_count":0,"quarantined_condition_count":0}}]}}\n' "$CATS_E3_EXACT_COMMIT"
        ;;
      *" create "*) printf '%s\n' '{"cat_id":"cat_fixture","operation_id":"op_create"}' ;;
      *" get "*) printf '%s\n' '{"id":"cat_fixture","desired":{"target":"running"},"observed":{"stable_state":"running","conditions":["ready"]}}' ;;
      *" operation wait op_create "*) printf '%s\n' '{"version":1,"operation_id":"op_create","workspace_id":"ws_fixture","target":"running","phase":"succeeded","terminal":{"kind":"succeeded","result":{"observed_target":"running"}}}' ;;
      *" operation wait op_endpoint "*) printf '%s\n' '{"version":1,"operation_id":"op_endpoint","workspace_id":"ws_fixture","target":"running","phase":"succeeded","terminal":{"kind":"succeeded","result":{"observed_target":"running"}}}' ;;
      *" operation wait op_delete "*) printf '%s\n' '{"version":1,"operation_id":"op_delete","workspace_id":"ws_fixture","target":"deleted","phase":"succeeded","terminal":{"kind":"succeeded","result":{"observed_target":"deleted"}}}' ;;
      *) exit 64 ;;
    esac
    ;;
  curl)
    output=/dev/null headers= method=GET url= write_out=false
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --output|--dump-header|--request|--header|--proto|--max-time|--max-filesize|--write-out|--data-binary)
          [[ $1 == --output ]] && output=$2
          [[ $1 == --dump-header ]] && headers=$2
          [[ $1 == --request ]] && method=$2
          [[ $1 == --write-out ]] && write_out=true
          shift 2
          ;;
        --fail|--silent|--show-error|--tlsv1.2) shift ;;
        https://*) url=$1; shift ;;
        *) exit 64 ;;
      esac
    done
    status=200 body='{}'
    case "$url|$method" in
      */healthz*) ;;
      */billing/usage*'|GET')
        if [[ -f "$CATS_E3_FIXTURE_USAGE_STATE" ]]; then
          usage_sequence=2
        else
          usage_sequence=1
          : >"$CATS_E3_FIXTURE_USAGE_STATE"
        fi
        body=$(printf '{"workspace_id":"ws_fixture","status":"provisional","latest_interval_end_unix_ms":2000,"details":[{"interval_start_unix_ms":1000,"interval_end_unix_ms":2000,"resource_type":"cat","resource_id":"cat_fixture","attributed_cat_id":"cat_fixture","metric":"cpu_usec","quantity":"1","unit":"microsecond","source_id":"node/node_fixture/cat/cat_fixture","source_epoch":"33333333333333333333333333333333","end_sequence":%s},{"interval_start_unix_ms":1000,"interval_end_unix_ms":2000,"resource_type":"cat","resource_id":"cat_fixture","attributed_cat_id":"cat_fixture","metric":"memory_byte_millis","quantity":"1024","unit":"byte_millisecond","source_id":"node/node_fixture/cat/cat_fixture","source_epoch":"33333333333333333333333333333333","end_sequence":%s}]}' "$usage_sequence" "$usage_sequence")
        ;;
      */endpoints*'|POST') status=202; body='{"desired_revision":2,"operation_id":"op_endpoint"}' ;;
      */cats/cat_fixture*'|DELETE') status=202; body='{"desired_revision":3,"operation_id":"op_delete"}' ;;
      *) exit 64 ;;
    esac
    [[ -z $headers ]] || printf 'HTTP/1.1 %s Fixture\r\nContent-Type: application/json\r\n\r\n' "$status" >"$headers"
    [[ $output == /dev/null ]] || printf '%s\n' "$body" >"$output"
    [[ $write_out == false ]] || printf '%s' "$status"
    ;;
  journalctl) printf '%s\n' 'fixture journal is bounded and nonsecret' ;;
  systemctl)
    [[ -z ${CATS_TOKEN:-} ]] || exit 65
    case "$1" in
      show)
        if [[ -f "$CATS_E3_FIXTURE_SYSTEMCTL_STATE" ]]; then
          printf '%032d\n' 2
        else
          printf '%032d\n' 1
        fi
        ;;
      restart) : >"$CATS_E3_FIXTURE_SYSTEMCTL_STATE" ;;
      is-active) exit 0 ;;
      *) exit 64 ;;
    esac
    ;;
  runtime-e3-probe)
    [[ -z ${CATS_TOKEN:-} ]] || exit 65
    case "$1" in
      guest-sync)
        run_id=
        while [[ $# -gt 0 ]]; do
          [[ $1 == --run-id ]] && { run_id=$2; break; }
          shift
        done
        printf '{"version":1,"cat_id":"cat_fixture","run_id":"%s","marker_path":"/var/lib/cats-e3/%s","before_remote_generation":1,"after_remote_generation":2,"after_remote_head":{"generation":2},"strict_flush_remote_durable":true}\n' "$run_id" "$run_id"
        ;;
      snapshot)
        printf '%s\n' '{"version":1,"cat_id":"cat_fixture","runtime_incarnation":"11111111111111111111111111111111","guest_boot_id":"22222222222222222222222222222222","vmm_scope_id":"cats-fixture.scope","root_volume_id":"vol_fixture","root_attachment_id":"att_fixture","root_attachment_epoch":1,"root_remote_head":{"generation":2},"root_remote_generation":2,"strict_remote_durable":true}'
        ;;
      install-workload)
        workload_sha256=
        while [[ $# -gt 0 ]]; do
          [[ $1 == --workload-sha256 ]] && { workload_sha256=$2; break; }
          shift
        done
        printf '{"version":1,"cat_id":"cat_fixture","run_id":"v2-fixture-run","unit":"cats-e3-v2-fixture-run","path":"/run/cats/cats-e3-v2-fixture-run","port":8080,"workload_sha256":"%s","installed":true}\n' "$workload_sha256"
        ;;
      remove-workload)
        printf '%s\n' '{"version":1,"cat_id":"cat_fixture","run_id":"v2-fixture-run","removed":true}'
        ;;
      public-route)
        printf '%s\n' '{"version":1,"origin":"https://e3.fixture.test","run_id":"v2-fixture-run","http_guest_body":true,"websocket_guest_echo":true}'
        ;;
      *) exit 64 ;;
    esac
    ;;
  route-g5-http)
    [[ -z ${CATS_TOKEN:-} ]] || exit 65
    if [[ " $* " == *" --list "* ]]; then
      printf '%s\n' 'public_http_bytes_cross_one_route_lookup_and_one_node_tunnel: test'
    fi
    ;;
  route-g5-ws)
    [[ -z ${CATS_TOKEN:-} ]] || exit 65
    if [[ " $* " == *" --list "* ]]; then
      printf '%s\n' 'websocket_upgrade_and_frames_remain_raw_on_the_one_admitted_tunnel: test'
    fi
    ;;
  node-agent-tests)
    [[ -z ${CATS_TOKEN:-} ]] || exit 65
    if [[ " $* " == *" --list "* ]]; then
      printf '%s\n' \
        'runtime_cutover::cross_component_e2e::postgres_control_and_production_cutover_adopts_serving_relaxed_pending_pack_across_restart: test' \
        'runtime::reconciliation::clean_slate_probes::tests::full_scanner_seals_exact_root_and_persistent_kernel_nbd_mount_set: test' \
        'runtime::reconciliation::clean_slate_probes::tests::full_scanner_seals_exact_root_and_persistent_vhost_mount_set: test'
    fi
    ;;
  e3-guest-workload) exit 0 ;;
  *) exit 64 ;;
esac
"#;
        let labels = [
            "cats",
            "curl",
            "journalctl",
            "route-g5-http",
            "route-g5-ws",
            "node-agent-tests",
            "runtime-e3-probe",
            "e3-guest-workload",
            "systemctl",
        ];
        let mut binaries = Vec::new();
        for label in labels {
            let path = self._temp.path().join(label);
            fs::write(&path, fake).expect("write v2 fake executable");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .expect("make v2 fake executable");
            binaries.push((label, path));
        }

        let mut command = Command::new("bash");
        command
            .arg(self.root.join("deploy/metal/runtime-cutover-e2e.sh"))
            .args(["--exact-commit", &self.exact_commit])
            .args(["--block-path", "kernel-nbd"])
            .args(["--run-id", "v2-fixture-run"])
            .arg("--output-dir")
            .arg(output_dir)
            .arg("--build-receipt")
            .arg(&self.build_receipt)
            .arg("--release-manifest")
            .arg(&self.release_manifest)
            .args(["--guest-kernel", "fixture-guest-kernel"]);
        for (label, path) in &binaries {
            command.arg("--binary").arg(format!(
                "{label}={}@sha256:{}",
                path.display(),
                sha256(path)
            ));
        }
        command
            .arg("--config")
            .arg(format!("route-key-ring={}", self.config.display()))
            .args([
                "--key-fingerprint",
                "route=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ])
            .arg("--scenario-driver")
            .arg(
                self.root
                    .join("deploy/metal/runtime-cutover-v2-scenarios.sh"),
            )
            .env("CATS_E3_TIMEOUT_BIN", &self.timeout)
            .env("CATS_TOKEN", "fixture-token")
            .env("CATS_E3_CONTROL_ORIGIN", "https://control.fixture")
            .env("CATS_E3_WORKSPACE_ID", "ws_fixture")
            .env("CATS_E3_EXPECTED_NODES", "node_fixture")
            .env("CATS_E3_CAT_NAME", "fixture-cat")
            .env(
                "CATS_E3_BOOT_IMAGE_DIGEST",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .env("CATS_E3_ENDPOINT_NAME", "e3-web")
            .env("CATS_E3_ENDPOINT_HOSTNAME", "e3.fixture.test")
            .env("CATS_E3_NODE_SERVICE", "cats-noded.service")
            .env(
                "CATS_E3_FIXTURE_SYSTEMCTL_STATE",
                self._temp.path().join("systemctl-restarted"),
            )
            .env(
                "CATS_E3_FIXTURE_USAGE_STATE",
                self._temp.path().join("usage-progressed"),
            )
            .current_dir(&self.root);
        command.output().expect("run production v2 driver fixture")
    }
}

fn sha256(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("hash fixture file");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("sha256sum output is UTF-8")
        .split_whitespace()
        .next()
        .expect("sha256sum emitted a digest")
        .to_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "fixture failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn runtime_cutover_runner_requires_exact_coordinates() {
    let fixture = Fixture::new();
    let output = fixture.run(Path::new("relative-output"), "kernel-nbd", |_| {});
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("absolute output"));
}

#[test]
fn runtime_cutover_runner_rejects_mismatched_build_receipt() {
    let fixture = Fixture::new();
    fs::write(
        &fixture.build_receipt,
        "{\"exit_status\":0,\"output_frozen\":true,\"source_sha\":\"1111111111111111111111111111111111111111\"}\n",
    )
    .unwrap();
    let output = fixture.run(&fixture.output_dir("mismatch"), "kernel-nbd", |_| {});
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("build receipt"));
}

#[test]
fn runtime_cutover_runner_rejects_a_dirty_binary() {
    let fixture = Fixture::new();
    let output = fixture.run_with_binary_digest(
        &fixture.output_dir("dirty-binary"),
        "kernel-nbd",
        &"f".repeat(64),
        |_| {},
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected sha256"));
}

#[test]
fn runtime_cutover_runner_continues_and_cleans_after_a_case_failure() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("case-failure");
    let output = fixture.run(&output_dir, "kernel-nbd", |command| {
        command.env("CATS_E3_FIXTURE_FAIL_CASE", "durable-write-flush");
    });
    assert!(!output.status.success());

    let trace = fs::read_to_string(&fixture.trace).expect("read scenario trace");
    for case_id in CASES {
        assert!(trace.contains(&format!("run|{case_id}|kernel-nbd")));
        assert!(trace.contains(&format!("cleanup|{case_id}|kernel-nbd")));
    }
    assert!(trace.contains("diagnostics|durable-write-flush|kernel-nbd"));
    let results = fs::read_to_string(output_dir.join("scenario-results.jsonl")).unwrap();
    assert_eq!(results.lines().count(), CASES.len());
    assert!(results.contains("\"case_id\":\"delete-cleanup\""));
    assert_eq!(
        fs::read_to_string(output_dir.join("exit-code")).unwrap(),
        "1\n"
    );
}

#[test]
fn runtime_cutover_runner_writes_atomic_checksummed_artifacts() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("success");
    let output = fixture.run(&output_dir, "vhost-user", |_| {});
    assert_success(&output);

    for artifact in [
        "manifest.json",
        "scenario-results.jsonl",
        "component-journal-summary.txt",
        "case-receipts.jsonl",
        "final-inventory.json",
        "exit-code",
        "SHA256SUMS",
    ] {
        assert!(output_dir.join(artifact).is_file(), "missing {artifact}");
    }
    assert!(fs::read_dir(&output_dir).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with('.')));
    let checksums = Command::new("sha256sum")
        .args(["-c", "SHA256SUMS"])
        .current_dir(&output_dir)
        .output()
        .expect("verify evidence checksums");
    assert_success(&checksums);
}

#[test]
fn runtime_cutover_runner_redacts_and_bounds_diagnostics() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("redaction");
    let output = fixture.run(&output_dir, "kernel-nbd", |command| {
        command
            .env("CATS_E3_FIXTURE_FAIL_CASE", "route-http-ws")
            .env("CATS_E3_FIXTURE_SECRETS", "true");
    });
    assert!(!output.status.success());
    let journal = fs::read_to_string(output_dir.join("component-journal-summary.txt")).unwrap();
    for secret in [
        "fixture-token-must-not-survive",
        "fixture-password-must-not-survive",
        "fixture-private-key-must-not-survive",
    ] {
        assert!(!journal.contains(secret), "journal retained {secret}");
    }
    assert!(
        journal.contains("[REDACTED]"),
        "journal did not record a redaction marker: {journal}"
    );
    assert!(journal.contains("[TRUNCATED:"));
    assert!(journal.len() <= 131_072);
}

#[test]
fn runtime_cutover_runner_rejects_sensitive_final_inventory() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("sensitive-inventory");
    let output = fixture.run(&output_dir, "kernel-nbd", |command| {
        command.env("CATS_E3_FIXTURE_SENSITIVE_INVENTORY", "true");
    });
    assert!(!output.status.success());
    let inventory = fs::read_to_string(output_dir.join("final-inventory.json")).unwrap();
    assert!(!inventory.contains("fixture-token-must-not-survive"));
    assert!(inventory.contains("unavailable"));
}

#[test]
fn production_v2_driver_dispatches_real_cases_and_preserves_blocked_evidence() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("production-v2-driver");
    let output = fixture.run_v2_driver(&output_dir);
    assert!(
        !output.status.success(),
        "E9 must remain explicitly blocked"
    );

    let results = fs::read_to_string(output_dir.join("scenario-results.jsonl")).unwrap();
    for case_id in CASES {
        assert!(results.contains(&format!("\"case_id\":\"{case_id}\"")));
    }
    for passed in [
        "control-startup-schema",
        "node-registration-full-inventory",
        "cat-create-running",
        "durable-write-flush",
        "route-http-ws",
        "agent-restart-adoption",
        "volume-init-matrix",
        "delete-cleanup",
    ] {
        assert!(results.lines().any(|line| {
            line.contains(&format!("\"case_id\":\"{passed}\""))
                && line.contains("\"status\":\"passed\"")
        }));
    }
    for blocked in ["usage-final-terminal-receipt"] {
        assert!(results.lines().any(|line| {
            line.contains(&format!("\"case_id\":\"{blocked}\""))
                && line.contains("\"status\":\"blocked\"")
        }));
    }
    let state = fs::read_to_string(output_dir.join("runtime-state.json")).unwrap();
    assert!(state.contains("\"cat_id\":\"cat_fixture\""));
    let journal = fs::read_to_string(output_dir.join("component-journal-summary.txt")).unwrap();
    assert!(journal.contains("BLOCKED_RECEIPT"));
    assert!(journal.contains("FOCUSED_RECEIPT"));
    assert!(!journal.contains("fixture-token"));
    let receipts = fs::read_to_string(output_dir.join("case-receipts.jsonl")).unwrap();
    assert!(receipts.contains("\"receipt_name\":\"public-route-receipt.json\""));
    assert!(receipts.contains("\"receipt_name\":\"volume-init-matrix-receipt.json\""));
    assert!(receipts.contains("\"receipt_name\":\"usage-live-delivery-receipt.json\""));
    assert!(receipts.contains("\"receipt_name\":\"blocked-receipt.json\""));
    assert!(!receipts.contains("fixture-token"));
}
