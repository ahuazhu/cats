use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

const CASES: [&str; 11] = [
    "control-startup-schema",
    "node-registration-full-inventory",
    "cat-create-running",
    "durable-write-flush",
    "route-http-ws",
    "route-v2-rotation-disable-live-delivery",
    "agent-restart-adoption",
    "volume-init-matrix",
    "v3-aws-host-fence-authority",
    "delete-cleanup",
    "usage-source-terminal-receipts",
];

const POST_BLOCK_PATH_CASES: [&str; 1] = ["usage-target-terminal-receipt"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// The E3 runner rejects sticky/world-writable state ancestry (the gate
/// container's /tmp) and the repository bind mount on a macOS Docker host is
/// virtiofs with unreliable link-count/inode re-resolution, so fixture
/// scratch prefers the gate's ext4-backed target volume. Plain hosts keep
/// their ambient temp directory.
fn fixture_scratch_base() -> PathBuf {
    // The native build host has neither the gate volume nor a writable
    // checkout, but relocates the cargo target via CARGO_TARGET_DIR with
    // non-sticky root-owned ancestry, which the E3 runner accepts.
    if let Some(directory) = std::env::var_os("CATS_LINUX_TARGET_DIRECTORY")
        .or_else(|| std::env::var_os("CARGO_TARGET_DIR"))
    {
        let base = PathBuf::from(directory).join("cutover-contract-fixture-tmp");
        std::fs::create_dir_all(&base).expect("create cutover fixture scratch base");
        return base
            .canonicalize()
            .expect("canonicalize cutover fixture scratch base");
    }
    // macOS's $TMPDIR sits under the /var -> private/var symlink, which the
    // O_NOFOLLOW ancestry walk rejects; canonicalize resolves it away.
    std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize ambient temp scratch base")
}

fn git_head(root: &Path) -> String {
    // The Linux gate mounts a worktree whose .git file points at the host
    // repository, so `git rev-parse` cannot work there; the gate exports the
    // exact provenance head instead.
    if let Ok(head) = std::env::var("CATS_SOURCE_PROVENANCE_HEAD") {
        let head = head.trim().to_owned();
        if !head.is_empty() {
            return head;
        }
    }
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

#[allow(dead_code)]
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    exact_commit: String,
    build_receipt: PathBuf,
    release_manifest: PathBuf,
    installer_receipt: PathBuf,
    binary: PathBuf,
    config: PathBuf,
    timeout: PathBuf,
    timeout_trace: PathBuf,
    trace: PathBuf,
    state_directory: PathBuf,
}

#[allow(dead_code)]
impl Fixture {
    fn new() -> Self {
        let root = workspace_root();
        let exact_commit = git_head(&root);
        let temp = tempfile::tempdir_in(fixture_scratch_base()).expect("runtime cutover fixture");
        let build_receipt = temp.path().join("build-receipt.json");
        let release_manifest = temp.path().join("release-manifest.json");
        let installer_receipt = temp.path().join("installer-receipt.json");
        let binary = temp.path().join("cats-noded");
        let config = temp.path().join("cats-public.conf");
        let timeout = temp.path().join("timeout");
        let timeout_trace = temp.path().join("timeout-trace");
        let trace = temp.path().join("trace");
        let state_directory = temp.path().join("persistent-state");
        fs::create_dir(&state_directory).expect("create persistent-state fixture");
        fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))
            .expect("protect persistent-state fixture");

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
        fs::write(&installer_receipt, "{}\n").expect("write untrusted installer receipt");
        fs::write(&binary, "fixture binary\n").expect("write binary fixture");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))
            .expect("make binary fixture executable");
        fs::write(&config, "public_setting=true\n").expect("write config fixture");
        fs::write(
            &timeout,
            r#"#!/usr/bin/env bash
set -euo pipefail
[[ -z ${CATS_E3_FIXTURE_TIMEOUT_TRACE:-} ]] || printf '%s\n' "$*" >>"$CATS_E3_FIXTURE_TIMEOUT_TRACE"
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
            installer_receipt,
            binary,
            config,
            timeout,
            timeout_trace,
            trace,
            state_directory,
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
            .arg("--state-directory")
            .arg(&self.state_directory)
            .arg("--build-receipt")
            .arg(&self.build_receipt)
            .arg("--release-manifest")
            .arg(&self.release_manifest)
            .arg("--release-manifest-sha256")
            .arg(format!("sha256:{}", sha256(&self.release_manifest)))
            .arg("--installer-receipt")
            .arg(&self.installer_receipt)
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
            .env("CATS_E3_FIXTURE_TIMEOUT_TRACE", &self.timeout_trace)
            .env("CATS_E3_FIXTURE_TRACE", &self.trace)
            .env(
                "CATS_E3_FIXTURE_CATALOG",
                self.root
                    .join("deploy/metal/runtime-cutover-e2e-catalog.v1.json"),
            )
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
        --disable|--fail|--silent|--show-error|--tlsv1.2|--tlsv1.3|--http1.1) shift ;;
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
        body=$(printf '{"workspace_id":"ws_fixture","status":"provisional","latest_interval_end_unix_ms":2000,"details":[{"interval_start_unix_ms":1000,"interval_end_unix_ms":2000,"resource_type":"cat","resource_id":"cat_fixture","attributed_cat_id":"cat_fixture","metric":"cpu_usec","quantity":"1","unit":"microsecond","source_id":"node/node_fixture/cat/cat_fixture","source_epoch":"session:fixture:runtime:fixture:processes:1","end_sequence":%s},{"interval_start_unix_ms":1000,"interval_end_unix_ms":2000,"resource_type":"cat","resource_id":"cat_fixture","attributed_cat_id":"cat_fixture","metric":"memory_byte_millis","quantity":"1024","unit":"byte_millisecond","source_id":"node/node_fixture/cat/cat_fixture","source_epoch":"session:fixture:runtime:fixture:processes:1","end_sequence":%s}]}' "$usage_sequence" "$usage_sequence")
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
        printf '{"version":1,"cat_id":"cat_fixture","run_id":"v2-fixture-run","unit":"cats-e3-v2-fixture-run","path":"/run/cats/cats-e3-v2-fixture-run","port":8080,"workload_sha256":"%s","guest_reread_sha256":"%s","guest_file_fsynced":true,"unit_main_pid":"42","unit_main_executable":"/run/cats/cats-e3-v2-fixture-run","installed":true}\n' "$workload_sha256" "$workload_sha256"
        ;;
      remove-workload)
        printf '%s\n' '{"version":1,"cat_id":"cat_fixture","run_id":"v2-fixture-run","removed":true}'
        ;;
      public-route)
        printf '%s\n' '{"version":1,"origin":"https://e3.fixture.test","run_id":"v2-fixture-run","http_guest_body":true,"websocket_guest_echo":true}'
        ;;
      public-route-closed)
        printf '%s\n' '{"version":1,"kind":"route_v2_public_admission_closed_v1","origin":"https://e3.fixture.test","path":"/e3/v2-fixture-run","run_id":"v2-fixture-run","tls_reachable":true,"http_status":503,"content_type":"text/plain","retry_after_seconds":1,"content_encoding_absent":true,"body_sha256":"sha256:3993919ba29fc397f3bbc6bf5d814e9caa9f184b557eb9c5fd7a59d45a2ac609","terminal_marker":"public_ingress_reachable_route_v2_closed"}'
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
            .arg("--release-manifest-sha256")
            .arg(format!("sha256:{}", sha256(&self.release_manifest)))
            .arg("--installer-receipt")
            .arg(&self.installer_receipt)
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

    fn run_post_preflight(
        &self,
        output_dir: &Path,
        configure: impl FnOnce(&mut Command),
    ) -> Output {
        let runner = self.root.join("deploy/metal/runtime-cutover-e2e.sh");
        let driver = self
            .root
            .join("deploy/metal/tests/runtime-cutover-e2e-scenario-fixture.sh");
        let filter = self
            .root
            .join("deploy/metal/runtime-cutover-evidence-filter.py");
        let script = r#"
set -euo pipefail
source "$1"
output_dir=$2
timeout_bin=$3
scenario_driver=$4
filter=$5
catalog=$6
block_path=kernel-nbd
scratch=$output_dir/.scratch
mkdir -m 0700 "$output_dir" "$scratch"
results_work=$scratch/scenario-results.jsonl
journal_work=$scratch/component-journal-summary.txt
evidence_work=$scratch/case-evidence.jsonl
: >"$results_work"
: >"$journal_work"
: >"$evidence_work"
case_ids=()
case_deadlines=()
case_cleanup_deadlines=()
case_expected_outcomes=()
case_required_evidence=()
while IFS= read -r case_record; do
  case_ids+=("$(jq -r '.case_id' <<<"$case_record")")
  case_deadlines+=("$(jq -r '.deadline_seconds' <<<"$case_record")")
  case_cleanup_deadlines+=("$(jq -r '.cleanup_deadline_seconds' <<<"$case_record")")
  case_expected_outcomes+=("$(jq -c '.expected_outcome' <<<"$case_record")")
  case_required_evidence+=("$(jq -c '.required_evidence' <<<"$case_record")")
done < <(jq -S -c '
  .framework_required_evidence as $framework
  | .cases[]
  | .required_evidence = (.required_evidence + $framework)' "$catalog")
cats_e3_run_cases_post_preflight
jq -S -c -n --argjson passed "$passed_cases" --argjson blocked "$blocked_cases" --argjson failed "$failed_cases" \
  '{passed:$passed,blocked:$blocked,failed:$failed}' >"$output_dir/case-counts.json"
"#;
        let mut command = Command::new("bash");
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").expect("test PATH"))
            .args(["-c", script, "runtime-cutover-post-preflight"])
            .arg(runner)
            .arg(output_dir)
            .arg(&self.timeout)
            .arg(driver)
            .arg(filter)
            .arg(
                self.root
                    .join("deploy/metal/runtime-cutover-e2e-catalog.v1.json"),
            )
            .env("CATS_E3_FIXTURE_MODE", "enabled")
            .env("CATS_E3_FIXTURE_TIMEOUT_TRACE", &self.timeout_trace)
            .env("CATS_E3_FIXTURE_TRACE", &self.trace)
            .env(
                "CATS_E3_FIXTURE_CATALOG",
                self.root
                    .join("deploy/metal/runtime-cutover-e2e-catalog.v1.json"),
            )
            .current_dir(&self.root);
        configure(&mut command);
        command.output().expect("run post-preflight E3 fixture")
    }
}

#[test]
fn runner_rebuilds_declared_coordinates_after_clearing_wrong_ambient_values() {
    let root = workspace_root();
    let runner = root.join("deploy/metal/runtime-cutover-e2e.sh");
    let script = r#"
set -euo pipefail
source "$1"
control_origin=https://control.example.test
workspace_id=workspace_e3
qualification_node=node_qualification
cat_name=e3-cat
boot_image_digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
endpoint_name=e3-web
endpoint_hostname=e3.example.test
installed_noded_path=/opt/cats/bin/cats-noded
token_file=/private/staged/control-token
expected_nodes=(node_other node_qualification)
export CATS_TOKEN=wrong-secret
export CATS_CONFIG_DIR=/wrong/ephemeral/cli-state
export CATS_E3_CONTROL_ORIGIN=https://wrong.example.test
export CATS_E3_WORKSPACE_ID=wrong-workspace
export CATS_E3_EXPECTED_NODES=wrong-node
export CATS_E3_QUALIFICATION_NODE_ID=wrong-node
cats_e3_clear_ambient
cats_e3_export_qualification_environment
test -z "${CATS_TOKEN:-}"
test -z "${CATS_CONFIG_DIR:-}"
test "$CATS_E3_CONTROL_ORIGIN" = "$control_origin"
test "$CATS_E3_WORKSPACE_ID" = "$workspace_id"
test "$CATS_E3_EXPECTED_NODES" = node_other,node_qualification
test "$CATS_E3_QUALIFICATION_NODE_ID" = "$qualification_node"
test "$CATS_E3_TOKEN_FILE" = "$token_file"
"#;
    let output = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args(["-c", script, "runtime-cutover-coordinate-fixture"])
        .arg(runner)
        .output()
        .expect("run coordinate rebuild fixture");
    assert_success(&output);
}

#[test]
fn runner_rejects_labels_that_alias_the_same_scenario_environment_name() {
    let runner = workspace_root().join("deploy/metal/runtime-cutover-e2e.sh");
    let script = r#"
set -euo pipefail
source "$1"
cats_e3_environment_labels_are_unique true cats=/one runtime-e3-probe=/two
if cats_e3_environment_labels_are_unique true runtime-e3-probe=/one runtime_e3_probe=/two; then
  exit 1
fi
if cats_e3_environment_labels_are_unique true runtime-e3-probe=/one runtime-e3-probe-sha256=/two; then
  exit 1
fi
if cats_e3_environment_labels_are_unique true runtime-e3-probe=/one runtime_e3_probe_sha256=/two; then
  exit 1
fi
if cats_e3_environment_labels_are_unique true runtime-e3-probe-sha256=/two runtime-e3-probe=/one; then
  exit 1
fi
cats_e3_environment_labels_are_unique false route-key-ring=/one route-key-ring-sha256=/two
"#;
    let output = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args(["-c", script, "runtime-cutover-label-fixture"])
        .arg(runner)
        .output()
        .expect("run environment label collision fixture");
    assert_success(&output);
}

#[test]
fn runner_keeps_the_production_cutover_key_out_of_staged_authority() {
    let runner = include_str!("../../../deploy/metal/runtime-cutover-e2e.sh");
    assert!(runner.contains("--production-cutover-operator-private-key-file"));
    assert!(runner.contains("production_cutover_operator_private_key_file_count -eq 1"));
    assert!(runner.contains("cats_e3_validate_private_key_input"));
    for required in [
        "getattr(os, \"O_NOFOLLOW\", 0)",
        "getattr(os, \"O_DIRECTORY\", 0)",
        "before.st_nlink != 1",
        "effective_owner[0] == 0 and effective_owner != (0, 0)",
        "stat.S_IMODE(before.st_mode) != 0o600",
        "not 1 <= before.st_size <= 16_384",
        "identity(os.fstat(descriptor)) != identity(before)",
    ] {
        assert!(
            runner.contains(required),
            "missing private-key guard {required}"
        );
    }
    for forbidden in [
        "export CATS_E3_PRODUCTION_CUTOVER_OPERATOR_PRIVATE_KEY_FILE",
        "stage_input production-cutover-operator-private-key",
        "remember_original production-cutover-operator-private-key",
        "production_cutover_operator_private_key_sha256",
    ] {
        assert!(
            !runner.contains(forbidden),
            "private-key authority leaked through {forbidden}"
        );
    }

    let temp =
        tempfile::tempdir_in(fixture_scratch_base()).expect("private-key validation fixture");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("protect private-key fixture parent");
    let script = r#"
set -euo pipefail
source "$1"
parent=$2
key=$parent/operator.pem
printf '%s' private-key-fixture >"$key"
chmod 0600 "$key"
cats_e3_validate_private_key_input "$key"
! cats_e3_validate_private_key_input relative.pem
! cats_e3_validate_private_key_input "$parent/missing.pem"
ln -s "$key" "$parent/symlink.pem"
! cats_e3_validate_private_key_input "$parent/symlink.pem"
rm "$parent/symlink.pem"
ln "$key" "$parent/hardlink.pem"
! cats_e3_validate_private_key_input "$key"
rm "$parent/hardlink.pem"
chmod 0644 "$key"
! cats_e3_validate_private_key_input "$key"
chmod 0600 "$key"
chmod 0770 "$parent"
! cats_e3_validate_private_key_input "$key"
chmod 0700 "$parent"
if [[ $(id -u) -eq 0 ]]; then
  chown 1:1 "$key"
  ! cats_e3_validate_private_key_input "$key"
fi
"#;
    let output = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args(["-c", script, "runtime-cutover-private-key-fixture"])
        .arg(workspace_root().join("deploy/metal/runtime-cutover-e2e.sh"))
        .arg(temp.path())
        .output()
        .expect("run private-key validation fixture");
    assert_success(&output);
    assert!(output.stdout.is_empty(), "private-key helper wrote stdout");
}

#[test]
fn runner_stages_the_route_rotation_key_without_manifesting_its_authority() {
    let runner = include_str!("../../../deploy/metal/runtime-cutover-e2e.sh");
    for required in [
        "cats_e3_stage_route_rotation_operator_key",
        "getattr(os, \"O_NOFOLLOW\", 0)",
        "os.O_EXCL",
        "(before.st_uid, before.st_gid) != (0, 0)",
        "before.st_nlink != 1",
        "stat.S_IMODE(before.st_mode) != 0o600",
        "not 1 <= before.st_size <= 65_536",
        "identity(os.fstat(source)) != identity(before)",
        "stat.S_IMODE(metadata.st_mode) != 0o700",
        "readonly cats_e3_volatile_private_root=/run/cats-runtime-cutover-e2e",
        "cats_e3_prepare_volatile_private_root",
        "with open(\"/proc/self/mountinfo\"",
        "cats_e3_prepare_private_stage \"$cats_e3_volatile_private_root\"",
        "CATS_E3_CONFIG_ROUTE_ROTATION_OPERATOR_KEY=$staged",
        "route_rotation_operator_key_seen=true",
    ] {
        assert!(
            runner.contains(required),
            "missing secret config guard {required}"
        );
    }
    for required_config in [
        "route-rotation-command-bundle",
        "route-rotation-recovery",
        "route-rotation-server-ca",
    ] {
        assert!(
            runner.contains(required_config),
            "missing Route rotation config {required_config}"
        );
    }
    for forbidden in [
        "route_rotation_operator_key_sha256",
        "remember_original \"config:route-rotation-operator-key\"",
        "stage_input \"config:route-rotation-operator-key\"",
        "--arg route_rotation_operator_key",
        "cats_e3_prepare_private_stage \"$state_directory\"",
    ] {
        assert!(
            !runner.contains(forbidden),
            "Route rotation private key leaked through {forbidden}"
        );
    }
    let secret_branch = runner
        .find("if [[ $label == route-rotation-operator-key ]]")
        .expect("Route rotation secret config branch");
    let branch_end = runner[secret_branch..]
        .find("continue")
        .map(|offset| secret_branch + offset)
        .expect("secret config branch bypasses generic staging");
    let generic_digest = runner[secret_branch..]
        .find("digest=$(sha256sum \"$canonical\"")
        .map(|offset| secret_branch + offset)
        .expect("generic config digest boundary");
    assert!(branch_end < generic_digest);
}

#[test]
fn route_rotation_key_stage_rejects_path_inode_and_mode_substitution() {
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .expect("read fixture uid");
    assert_success(&uid);
    if uid.stdout != b"0\n" {
        // The production runner itself requires root. The native/Linux root
        // gate executes the inode and ownership matrix below.
        return;
    }
    let root_parent = [Path::new("/root"), Path::new("/var/root")]
        .into_iter()
        .find(|path| path.is_dir())
        .expect("root-only fixture parent");
    let temp = tempfile::tempdir_in(root_parent).expect("Route rotation key fixture");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("protect Route rotation key fixture");
    let script = r#"
set -euo pipefail
source "$1"
root=$2
source_dir=$root/source
destination_dir=$root/destination
mkdir "$source_dir" "$destination_dir"
chmod 0700 "$source_dir" "$destination_dir"
key=$source_dir/operator.pem
printf '%s' route-rotation-private-key >"$key"
chmod 0600 "$key"
destination=$destination_dir/staged.pem
cats_e3_stage_route_rotation_operator_key "$key" "$destination"
cmp -s "$key" "$destination"
[[ $(stat -c '%a:%u:%g:%h:%s' "$destination") == 600:0:0:1:26 ]]
! cats_e3_stage_route_rotation_operator_key "$key" "$destination"
! cats_e3_stage_route_rotation_operator_key relative.pem "$destination_dir/relative.pem"
! cats_e3_stage_route_rotation_operator_key "$source_dir/missing.pem" "$destination_dir/missing.pem"
ln -s "$key" "$source_dir/symlink.pem"
! cats_e3_stage_route_rotation_operator_key "$source_dir/symlink.pem" "$destination_dir/symlink.pem"
unlink "$source_dir/symlink.pem"
ln "$key" "$source_dir/hardlink.pem"
! cats_e3_stage_route_rotation_operator_key "$key" "$destination_dir/hardlink.pem"
unlink "$source_dir/hardlink.pem"
chmod 0644 "$key"
! cats_e3_stage_route_rotation_operator_key "$key" "$destination_dir/mode.pem"
chmod 0600 "$key"
chmod 0750 "$source_dir"
! cats_e3_stage_route_rotation_operator_key "$key" "$destination_dir/source-parent.pem"
chmod 0700 "$source_dir"
chmod 0750 "$destination_dir"
! cats_e3_stage_route_rotation_operator_key "$key" "$destination_dir/destination-parent.pem"
chmod 0700 "$destination_dir"
ln -s "$source_dir" "$root/source-link"
! cats_e3_stage_route_rotation_operator_key "$root/source-link/operator.pem" "$destination_dir/ancestor.pem"
unlink "$root/source-link"
chown 1:1 "$key"
! cats_e3_stage_route_rotation_operator_key "$key" "$destination_dir/owner.pem"
"#;
    let output = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args(["-c", script, "runtime-cutover-route-rotation-key-fixture"])
        .arg(workspace_root().join("deploy/metal/runtime-cutover-e2e.sh"))
        .arg(temp.path())
        .output()
        .expect("run Route rotation key fixture");
    assert_success(&output);
    assert!(output.stdout.is_empty(), "secret staging wrote stdout");
}

fn assert_tree_has_no_secret(path: &Path, secret: &[u8]) {
    for entry in fs::read_dir(path).expect("read retained state directory") {
        let entry = entry.expect("read retained state entry");
        if entry
            .file_type()
            .expect("read retained state entry type")
            .is_dir()
        {
            assert_tree_has_no_secret(&entry.path(), secret);
            continue;
        }
        let bytes = fs::read(entry.path()).expect("read retained state file");
        assert!(
            !bytes.windows(secret.len()).any(|window| window == secret),
            "retained state contains private bytes at {}",
            entry.path().display()
        );
    }
}

fn assert_tree_has_no_private_input_artifacts(path: &Path, secrets: &[&str]) {
    for entry in fs::read_dir(path).expect("read retained artifact directory") {
        let entry = entry.expect("read retained artifact entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        assert!(
            !matches!(
                name.as_ref(),
                "invocation-secrets"
                    | "control-token"
                    | "production-cutover-operator-key"
                    | "route-rotation-operator-key"
            ) && !name.starts_with("invocation-")
                && !name.starts_with(".authorization."),
            "retained private input artifact {}",
            entry.path().display()
        );
        if entry
            .file_type()
            .expect("read retained artifact type")
            .is_dir()
        {
            assert_tree_has_no_private_input_artifacts(&entry.path(), secrets);
            continue;
        }
        let bytes = fs::read(entry.path()).expect("read retained artifact file");
        for secret in secrets {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "retained private input bytes at {}",
                entry.path().display()
            );
        }
    }
}

fn assert_private_stage_removed_without_secret(output_dir: &Path, secret: &str) {
    let stage =
        fs::read_to_string(output_dir.join("private-stage-path")).expect("read private stage path");
    assert!(
        !Path::new(stage.trim()).starts_with(output_dir),
        "private stage was created inside retained evidence"
    );
    assert!(
        !Path::new(stage.trim()).exists(),
        "private stage survived exit"
    );
    assert_tree_has_no_secret(output_dir, secret.as_bytes());
}

#[test]
fn runner_removes_private_token_stage_after_failure() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("private-stage-failure");
    let private_root = fixture.output_dir("private-stage-root-failure");
    fs::create_dir(&private_root).expect("create private stage root");
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))
        .expect("protect private stage root");
    let private_root = fs::canonicalize(private_root).expect("canonical private stage root");
    let runner = fixture.root.join("deploy/metal/runtime-cutover-e2e.sh");
    let secret = "fixture-control-token-must-not-survive";
    let script = r#"
set -euo pipefail
source "$1"
mkdir -m 0700 "$2"
cats_e3_prepare_private_stage "$4"
printf '%s\n' "$cats_e3_private_stage" >"$2/private-stage-path"
printf '%s' "$3" >"$cats_e3_private_stage/control-token"
chmod 0600 "$cats_e3_private_stage/control-token"
exit 23
"#;
    let output = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args(["-c", script, "runtime-cutover-private-stage-failure"])
        .arg(runner)
        .arg(&output_dir)
        .arg(secret)
        .arg(&private_root)
        .output()
        .expect("run private stage failure fixture");
    assert_eq!(output.status.code(), Some(23));
    assert_private_stage_removed_without_secret(&output_dir, secret);
}

#[test]
fn runner_removes_private_token_stage_after_term() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("private-stage-term");
    let private_root = fixture.output_dir("private-stage-root-term");
    fs::create_dir(&private_root).expect("create private stage root");
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))
        .expect("protect private stage root");
    let private_root = fs::canonicalize(private_root).expect("canonical private stage root");
    let runner = fixture.root.join("deploy/metal/runtime-cutover-e2e.sh");
    let secret = "fixture-control-token-must-not-survive-term";
    let script = r#"
set -euo pipefail
source "$1"
mkdir -m 0700 "$2"
cats_e3_prepare_private_stage "$4"
printf '%s\n' "$cats_e3_private_stage" >"$2/private-stage-path"
printf '%s' "$3" >"$cats_e3_private_stage/control-token"
chmod 0600 "$cats_e3_private_stage/control-token"
: >"$2/ready"
while :; do sleep 1; done
"#;
    let mut child = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args(["-c", script, "runtime-cutover-private-stage-term"])
        .arg(runner)
        .arg(&output_dir)
        .arg(secret)
        .arg(&private_root)
        .spawn()
        .expect("spawn private stage TERM fixture");
    for _ in 0..200 {
        if output_dir.join("ready").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        output_dir.join("ready").exists(),
        "TERM fixture did not become ready"
    );
    let signal = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send TERM to private stage fixture");
    assert!(signal.success());
    let status = child.wait().expect("wait for private stage TERM fixture");
    assert_eq!(status.code(), Some(143));
    assert_private_stage_removed_without_secret(&output_dir, secret);
}

#[test]
fn runner_uses_only_the_fixed_root_private_tmpfs_stage_in_production() {
    if !Path::new("/proc/self/mountinfo").is_file() {
        return;
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .expect("read fixture uid");
    assert_success(&uid);
    if uid.stdout != b"0\n" {
        // The production runner itself requires root. The native/Linux root
        // gate executes the fixed tmpfs and cleanup checks below.
        return;
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").expect("read fixture mountinfo");
    if !mountinfo
        .lines()
        .any(|line| line.contains(" /run ") && line.contains(" tmpfs "))
    {
        // Root inside the unprivileged workspace gate container has no /run
        // tmpfs; the privileged PID-1 phase and the native root gate execute
        // the fixed-stage checks below.
        return;
    }
    let stage_name = format!("invocation-{:064x}", std::process::id());
    let script = r#"
set -euo pipefail
source "$1"
cats_e3_prepare_volatile_private_root
[[ $cats_e3_volatile_private_root == /run/cats-runtime-cutover-e2e ]]
[[ $(stat -f -c '%T' "$cats_e3_volatile_private_root") == tmpfs ]]
[[ $(stat -c '%u:%g:%a' "$cats_e3_volatile_private_root") == 0:0:700 ]]
cats_e3_prepare_private_stage "$cats_e3_volatile_private_root" "$2"
printf '%s' fixture-volatile-secret >"$cats_e3_private_stage/control-token"
chmod 0600 "$cats_e3_private_stage/control-token"
"#;
    let output = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args(["-c", script, "runtime-cutover-private-tmpfs-stage"])
        .arg(workspace_root().join("deploy/metal/runtime-cutover-e2e.sh"))
        .arg(&stage_name)
        .output()
        .expect("run fixed volatile stage fixture");
    assert_success(&output);
    assert!(!Path::new("/run/cats-runtime-cutover-e2e")
        .join(stage_name)
        .exists());
}

#[test]
fn operator_e3_window_closes_and_verifies_every_early_failure_or_term() {
    let root = workspace_root();
    let library = root.join("deploy/metal/runtime-cutover-e3-window.sh");
    let fixture = root.join("deploy/metal/tests/runtime-cutover-e3-window-fixture.sh");
    let temp = tempfile::tempdir_in(fixture_scratch_base()).expect("E3 window fixture");
    for checkpoint in ["open", "plan", "show", "before-switch"] {
        for (failure_mode, expected_status) in [("failure", 23), ("term", 143)] {
            let trace = temp
                .path()
                .join(format!("{checkpoint}-{failure_mode}.trace"));
            let output = Command::new("bash")
                .arg(&fixture)
                .arg(&library)
                .arg(&trace)
                .arg(checkpoint)
                .arg(failure_mode)
                .output()
                .expect("run E3 window failure fixture");
            assert_eq!(
                output.status.code(),
                Some(expected_status),
                "wrong status at {checkpoint}/{failure_mode}: stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
            let events = fs::read_to_string(trace).expect("read E3 window trace");
            assert!(
                events.ends_with("emergency-close\ne12\n"),
                "cleanup order changed at {checkpoint}/{failure_mode}: {events}"
            );
            assert!(!events.contains("saved-close"));
            assert!(!events.contains("re-cordon"));
        }
    }

    let trace = temp.path().join("after-switch.trace");
    let output = Command::new("bash")
        .arg(&fixture)
        .arg(&library)
        .arg(&trace)
        .arg("after-switch")
        .arg("failure")
        .output()
        .expect("run saved-plan E3 window fixture");
    assert_eq!(output.status.code(), Some(23));
    let events = fs::read_to_string(trace).expect("read saved-plan E3 window trace");
    assert!(events.ends_with("saved-close\ne12\n"));
    assert!(!events.contains("emergency-close"));

    for failure_mode in ["term-in-re-cordon", "term-in-saved-close"] {
        let trace = temp.path().join(format!("{failure_mode}.trace"));
        let output = Command::new("bash")
            .arg(&fixture)
            .arg(&library)
            .arg(&trace)
            .arg("finish")
            .arg(failure_mode)
            .output()
            .expect("run in-cleanup TERM fixture");
        assert_eq!(
            output.status.code(),
            Some(143),
            "cleanup TERM lost at {failure_mode}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let events = fs::read_to_string(trace).expect("read in-cleanup TERM trace");
        assert!(events.ends_with("re-cordon\nsaved-close\ne12\n"));
        for effect in ["re-cordon", "saved-close", "e12"] {
            assert_eq!(
                events.lines().filter(|event| *event == effect).count(),
                1,
                "{effect} repeated at {failure_mode}: {events}"
            );
        }
    }

    let trace = temp.path().join("term-and-close-failure.trace");
    let output = Command::new("bash")
        .arg(&fixture)
        .arg(&library)
        .arg(&trace)
        .arg("finish")
        .arg("term-and-close-failure")
        .output()
        .expect("run cleanup-error precedence fixture");
    assert_eq!(output.status.code(), Some(57));
    let events = fs::read_to_string(trace).expect("read cleanup-error precedence trace");
    assert!(events.ends_with("re-cordon\nsaved-close\ne12\n"));
}

#[test]
fn emergency_ingress_close_plan_validator_accepts_only_the_closed_shape() {
    let root = workspace_root();
    let fixture = root.join("deploy/metal/tests/runtime-cutover-ingress-close-plan-fixture.sh");
    let validator = root.join("deploy/metal/runtime-cutover-ingress-close-plan.sh");
    let output = Command::new("bash")
        .arg(fixture)
        .arg(validator)
        .output()
        .expect("run emergency ingress close plan fixtures");
    assert_success(&output);
}

#[test]
fn runbook_installs_the_allowlisted_early_guard_before_public_ingress() {
    let root = workspace_root();
    let runbook = fs::read_to_string(root.join("docs/production-cutover-runbook.md"))
        .expect("read production cutover runbook");
    let validator =
        fs::read_to_string(root.join("deploy/metal/runtime-cutover-ingress-close-plan.sh"))
            .expect("read emergency close plan validator");
    for target in [
        "-target=module.cats_kubernetes.kubernetes_namespace_v1.cats",
        "-target=module.cats_kubernetes.kubernetes_manifest.ingress_class_params",
        "-target=module.cats_kubernetes.kubernetes_ingress_class_v1.public",
        "-target=module.cats_kubernetes.kubernetes_ingress_v1.public",
        "-target=aws_route53_record.public",
    ] {
        assert!(
            runbook.contains(target),
            "missing emergency target {target}"
        );
    }
    assert!(runbook.contains("runtime-cutover-ingress-close-plan.sh"));
    assert!(validator.contains("select(.mode == \"managed\" and .change.actions != [\"no-op\"])"));
    for gate in [
        ".prior_state.values | resources",
        ".planned_values | resources",
        ".change.after_unknown | .. | booleans",
        ".change.actions == [\"delete\"] and .change.after == null",
        ".values.metadata[0].labels[\"cats.run/ingress\"]] == [\"disabled\"]",
    ] {
        assert!(
            validator.contains(gate),
            "missing emergency plan gate {gate}"
        );
    }
    let guard = runbook.find("cats_e3_window_install_guard").unwrap();
    let initiated = runbook
        .find("\ncats_e3_window_mark_open_initiated\n")
        .unwrap();
    let open = runbook
        .find("-qualification-ingress-open.tfplan \\")
        .unwrap();
    assert!(guard < initiated && initiated < open);
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

#[allow(dead_code)]
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
fn runtime_cutover_runner_rejects_untrusted_installer_receipt() {
    let fixture = Fixture::new();
    let output = fixture.run(
        &fixture.output_dir("untrusted-installer-receipt"),
        "kernel-nbd",
        |_| {},
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("canonical production installation receipt"));
}

#[test]
fn runtime_cutover_runner_rejects_a_dirty_binary() {
    let runner = include_str!("../../../deploy/metal/runtime-cutover-e2e.sh");
    assert!(runner.contains("digest must come from the approved manifest and installer receipt"));
    assert!(runner.contains("[[ sha256:$digest == \"$expected_sha256\""));
    assert!(runner.contains("stage_input \"binary:$label\""));
}

#[test]
fn runtime_cutover_catalog_is_closed_release_bound_and_all_pass() {
    let catalog: serde_json::Value = serde_json::from_str(include_str!(
        "../../../deploy/metal/runtime-cutover-e2e-catalog.v1.json"
    ))
    .expect("parse canonical qualification catalog");
    let object = catalog.as_object().expect("catalog object");
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "cases",
            "framework_required_evidence",
            "post_block_path_cases",
            "qualification_admission_required_evidence",
            "version"
        ]
    );
    assert_eq!(catalog["version"], 1);
    assert_eq!(
        catalog["framework_required_evidence"],
        serde_json::json!([{"filename":"cleanup-receipt.json","kind":"json"}])
    );
    assert_eq!(
        catalog["qualification_admission_required_evidence"],
        serde_json::json!([
            {"filename":"production-mutation-qualification-begin.receipt.json","kind":"json"},
            {"filename":"production-mutation-qualification-terminal.receipt.json","kind":"json"}
        ])
    );

    let cases = catalog["cases"].as_array().expect("catalog cases");
    assert_eq!(cases.len(), CASES.len());
    for (case, expected_id) in cases.iter().zip(CASES) {
        assert_eq!(case["case_id"], expected_id);
        assert_eq!(
            case["expected_outcome"],
            serde_json::json!({"kind":"passed"})
        );
        assert!(case["deadline_seconds"]
            .as_u64()
            .is_some_and(|value| value > 0));
        assert_eq!(
            case["cleanup_deadline_seconds"],
            if expected_id == "route-v2-rotation-disable-live-delivery" {
                1800
            } else {
                60
            }
        );
        assert!(!case["required_evidence"]
            .as_array()
            .expect("case evidence")
            .is_empty());
    }
    let post_cases = catalog["post_block_path_cases"]
        .as_array()
        .expect("post-block-path cases");
    assert_eq!(post_cases.len(), POST_BLOCK_PATH_CASES.len());
    for (case, expected_id) in post_cases.iter().zip(POST_BLOCK_PATH_CASES) {
        assert_eq!(case["case_id"], expected_id);
        assert_eq!(
            case["expected_outcome"],
            serde_json::json!({"kind":"passed"})
        );
        assert_eq!(case["deadline_seconds"], 600);
    }
    assert_eq!(
        post_cases[0]["required_evidence"],
        serde_json::json!([
            {"filename":"usage-target-terminal-request.json","kind":"json"},
            {"filename":"usage-target-terminal-receipt.json","kind":"json"},
            {"filename":"usage-target-terminal-verification.receipt.json","kind":"json"}
        ])
    );

    let runner = include_str!("../../../deploy/metal/runtime-cutover-e2e.sh");
    let builder = include_str!("../../../deploy/aws/tools/build-manual-release.sh");
    assert!(runner.contains(".build_inputs.files.qualification_catalog"));
    assert!(runner.contains("differs from the exact commit"));
    assert!(runner.contains("actual_json == \"$expected_json\""));
    assert!(runner.contains("route-rotation-operator-trust must use the canonical installed path"));
    assert!(runner.contains("value[\"release_commit_sha\"] != exact_commit"));
    assert!(runner.contains("route_v2_rotation_operator:{config_label:"));
    assert!(runner.contains("CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID"));
    assert!(runner.contains(
        "CATS_E3_QUALIFICATION_CATALOG_SHA256=sha256:$qualification_catalog_authority_sha256"
    ));
    assert!(runner.contains("qualification catalog digest changed"));
    assert!(runner.contains("--kill-after=\"$kill_after\""));
    assert!(runner.contains("cleanup_deadline=${case_cleanup_deadlines[$index]}"));
    assert!(builder.contains("--input-file \"qualification_catalog="));
}

#[test]
fn runtime_cutover_runner_continues_and_cleans_after_a_case_failure() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("case-failure");
    let output = fixture.run_post_preflight(&output_dir, |command| {
        command.env("CATS_E3_FIXTURE_FAIL_CASE", "durable-write-flush");
    });
    assert_success(&output);
    let trace = fs::read_to_string(&fixture.trace).expect("read scenario trace");
    for case_id in CASES {
        assert!(trace.contains(&format!("run|{case_id}|kernel-nbd")));
        assert!(trace.contains(&format!("cleanup|{case_id}|kernel-nbd")));
    }
    assert!(trace.contains("diagnostics|durable-write-flush|kernel-nbd"));
    let results = fs::read_to_string(output_dir.join("scenario-results.jsonl")).unwrap();
    assert_eq!(results.lines().count(), CASES.len());
    assert!(results
        .lines()
        .any(|line| line.contains("\"case_id\":\"durable-write-flush\"")
            && line.contains("\"status\":\"failed\"")));
}

#[test]
fn runtime_cutover_runner_writes_atomic_checksummed_artifacts() {
    let runner = include_str!("../../../deploy/metal/runtime-cutover-e2e.sh");
    for artifact in [
        "manifest.json",
        "scenario-results.jsonl",
        "component-journal-summary.txt",
        "case-evidence.jsonl",
        "qualification-catalog.v1.json",
        "final-inventory.json",
        "exit-code",
        "SHA256SUMS",
    ] {
        assert!(runner.contains(artifact), "runner omits {artifact}");
    }
    assert!(runner.contains("mv -f \"$checksums_tmp\" \"$output_dir/SHA256SUMS\""));
}

#[test]
fn runtime_cutover_runner_orders_qualification_and_closes_exact19() {
    let runner = include_str!("../../../deploy/metal/runtime-cutover-e2e.sh");
    let lifecycle_start = runner
        .rfind("qualification_begin_ok=false")
        .expect("production Qualification lifecycle");
    let lifecycle = &runner[lifecycle_start..];
    let begin = lifecycle
        .find("if cats_e3_qualification_begin; then")
        .expect("BeginQualification");
    let product = lifecycle
        .find("cats_e3_run_cases_post_preflight product")
        .expect("product case phase");
    let close = lifecycle
        .find("cats_e3_qualification_close \"$qualification_close_kind\"")
        .expect("durable close");
    let product_inventory = lifecycle
        .find("cats_e3_qualification_product_inventory \"$qualification_close_kind\"")
        .expect("post-close product inventory");
    let final_inventory = lifecycle
        .find("cats_e3_collect_final_inventory")
        .expect("post-close Fleet inventory");
    let wrappers = lifecycle
        .find("cats_e3_publish_qualification_zero_wrappers")
        .expect("zero wrappers");
    let terminalize = lifecycle
        .find("cats_e3_qualification_terminalize \"$qualification_close_kind\"")
        .expect("qualified Closed terminal receipt");
    let source = lifecycle
        .find("cats_e3_run_cases_post_preflight source")
        .expect("read-only Usage source closure");
    assert!(
        begin < product
            && product < close
            && close < product_inventory
            && product_inventory < final_inventory
            && final_inventory < wrappers
            && wrappers < terminalize
            && terminalize < source
    );
    assert!(lifecycle.contains("$qualification_close_kind != end_qualification"));
    assert!(lifecycle.contains("$qualification_terminalized != true"));

    let exact18_start = lifecycle
        .find("expected_output_names=(")
        .expect("exact18 output list");
    let exact18 = &lifecycle[exact18_start..];
    let exact18_end = exact18
        .find("\n)\nchecksum_names=()")
        .expect("exact18 output list boundary");
    let actual = exact18[..exact18_end]
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        [
            "case-evidence.jsonl",
            "component-journal-summary.txt",
            "exit-code",
            "final-inventory.json",
            "manifest.json",
            "production-mutation-qualification-begin.command-receipt.json",
            "production-mutation-qualification-begin.pending.json",
            "production-mutation-qualification-begin.receipt.json",
            "production-mutation-qualification-cleanup-inventory.receipt.json",
            "production-mutation-qualification-close.command-receipt.json",
            "production-mutation-qualification-close.pending.json",
            "production-mutation-qualification-final-admission-state.json",
            "production-mutation-qualification-final-fleet-closed.receipt.json",
            "production-mutation-qualification-product-inventory.receipt.json",
            "production-mutation-qualification-terminal.receipt.json",
            "qualification-catalog.v1.json",
            "runtime-state.json",
            "scenario-results.jsonl",
        ]
    );
    assert!(lifecycle.contains("LC_ALL=C sha256sum \"${checksum_names[@]}\""));
}

#[test]
fn runtime_cutover_runner_persists_exact_reentry_and_close_authority() {
    let runner = include_str!("../../../deploy/metal/runtime-cutover-e2e.sh");
    for required in [
        "--state-directory </absolute/persistent/root-only/directory>",
        "cats_e3_pin_private_directory \"$state_directory_requested\"",
        "state_directory=$state_directory_fd_path",
        "cats_e3_create_pinned_output_directory \"$output_parent_fd\"",
        "output_dir=$output_dir_fd_path",
        "flock -n \"$state_lock_fd\"",
        "qualification-state-binding.v1.json",
        "qualification-close-decision.v1.json",
        "cats.production-mutation-qualification-close-decision.v1",
        "configuration_manifest_sha256",
        "initial_runtime_state_sha256",
        "run_started_at_unix_seconds",
        "authority_schema_version:$authority_schema_version",
        "control_origin:$control_origin",
        "guest_kernel:$guest_kernel,host_kernel:$host_kernel",
        "build_receipt_sha256:$build_receipt_sha256",
        "installer_receipt_sha256:$installer_receipt_sha256",
        "runner_sha256:$runner_sha256,scenario_driver_sha256:$scenario_driver_sha256",
        "cats_cli_recovery_namespace:\"cats-cli\"",
        "export CATS_CONFIG_DIR=$persistent_cli_state_dir",
        "expected_node_ids:$expected_node_ids[0]",
        "qualification_node_id:$qualification_node_id",
        "route_rotation_operator_authority_id:$route_rotation_operator_authority_id",
        "route_rotation_route_deployment_id:$route_rotation_route_deployment_id",
        "route_rotation_command_bundle_sha256:$route_rotation_command_bundle_sha256",
        "route_rotation_recovery_sha256:$route_rotation_recovery_sha256",
        "route_rotation_server_ca_sha256:$route_rotation_server_ca_sha256",
        "exact source must expose the one frozen authority schema version 16",
    ] {
        assert!(
            runner.contains(required),
            "missing re-entry guard {required}"
        );
    }
    let decision = runner
        .rfind("qualification_close_decision=$state_directory/")
        .expect("load durable close decision");
    let begin = runner
        .rfind("if cats_e3_qualification_begin; then")
        .expect("BeginQualification invocation");
    assert!(
        decision < begin,
        "close decision must be loaded before Begin replay"
    );
    assert!(runner
        .contains("cats_e3_persist_close_decision \"$qualification_close_kind\" >/dev/null 2>&1"));
    assert!(runner.contains("cats_e3_run_qualification_operator qualification-close"));
    assert!(runner.contains("--close-kind \"$close_kind\" || return $?"));
    assert!(runner.contains("cats_e3_run_qualification_operator qualification-terminalize"));
}

#[test]
fn runner_exit_without_an_existing_begin_pending_has_zero_begin_or_close_effects() {
    let fixture = Fixture::new();
    let trace = fixture._temp.path().join("runner-exit-recovery.trace");
    let state = fixture._temp.path().join("runner-exit-recovery-state");
    fs::create_dir(&state).expect("create exit recovery state");
    let script = r#"
set -euo pipefail
source "$1"
trace=$2
state_directory=$3
qualification_lifecycle_attempted=true
qualification_begin_applied=false
qualification_close_applied=false
qualification_close_forbidden=false
qualification_close_kind=
cats_e3_qualification_begin() {
  printf '%s\n' forbidden-new-begin >>"$trace"
  return 91
}
cats_e3_resolve_existing_qualification_begin() {
  printf '%s\n' resolve-existing-only >>"$trace"
  return 1
}
cats_e3_forward_recover_g3_on_exit() { printf '%s\n' forbidden-g3 >>"$trace"; }
cats_e3_persist_close_decision() {
  printf '%s\n' forbidden-decision >>"$trace"
}
cats_e3_qualification_close() {
  printf '%s\n' forbidden-close >>"$trace"
}
if cats_e3_close_on_exit; then
  exit 90
fi
"#;
    let output = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args(["-c", script, "runtime-cutover-exit-recovery"])
        .arg(fixture.root.join("deploy/metal/runtime-cutover-e2e.sh"))
        .arg(&trace)
        .arg(&state)
        .output()
        .expect("run exit recovery lifecycle fixture");
    assert_success(&output);
    assert_eq!(
        fs::read_to_string(trace).unwrap(),
        "resolve-existing-only\n"
    );
}

#[test]
fn qualification_begin_existing_only_never_prepares_missing_authority() {
    let fixture = Fixture::new();
    let state = fixture._temp.path().join("missing-begin-state");
    fs::create_dir(&state).expect("create missing Begin state");
    let script = r#"
import importlib.util
import pathlib
import sys
import types

operator_path = pathlib.Path(sys.argv[1])
state = pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("production_mutation_admission", operator_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.validate_qualification_authority_inputs = lambda _args: {
    "qualification_id": "fixture-qualification",
}
def forbidden_prepare(*_args, **_kwargs):
    raise AssertionError("existing-only resolution attempted to prepare a command")
module.ensure_qualification_pending = forbidden_prepare
args = types.SimpleNamespace(state_directory=state, existing_pending_only=True)
try:
    module.qualification_begin(args)
except module.AdmissionError as error:
    assert str(error) == "Qualification Begin pending authority is unavailable"
else:
    raise AssertionError("missing deterministic Begin pending was accepted")
assert list(state.iterdir()) == []
"#;
    let output = Command::new("python3")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args(["-c", script])
        .arg(
            fixture
                .root
                .join("deploy/aws/production-mutation-admission.py"),
        )
        .arg(&state)
        .output()
        .expect("run existing-only Begin operator fixture");
    assert_success(&output);
}

#[test]
fn runner_binds_emergency_before_g3_and_reentry_cannot_upgrade_to_end() {
    let fixture = Fixture::new();
    let trace = fixture
        ._temp
        .path()
        .join("runner-emergency-before-g3.trace");
    let state = fixture
        ._temp
        .path()
        .join("runner-emergency-before-g3.state");
    fs::create_dir(&state).expect("create emergency decision state");
    let script = r#"
set -euo pipefail
source "$1"
trace=$2
state_directory=$3
mode=$4
decision=$state_directory/qualification-close-decision.v1.json
qualification_lifecycle_attempted=true
qualification_begin_applied=true
qualification_close_applied=false
qualification_close_forbidden=false
qualification_terminalized=false
qualification_close_kind=
if [[ $mode == resume ]]; then
  if [[ -f $decision ]]; then
    qualification_close_kind=$(cat "$decision")
  else
    qualification_close_kind=end_qualification
  fi
fi
cats_e3_persist_close_decision() {
  if [[ -f $decision ]]; then
    test "$(cat "$decision")" = "$1"
  else
    (umask 077; printf '%s\n' "$1" >"$decision")
    sync -f "$state_directory"
  fi
  printf 'decision:%s\n' "$1" >>"$trace"
}
cats_e3_forward_recover_g3_on_exit() {
  printf 'g3:%s\n' "$mode" >>"$trace"
  if [[ $mode == kill ]]; then
    kill -KILL $$
  fi
}
cats_e3_qualification_close() {
  printf 'close:%s\n' "$1" >>"$trace"
  test "$1" = emergency_close
  qualification_close_applied=true
}
cats_e3_qualification_product_inventory() { :; }
cats_e3_collect_final_inventory() { :; }
cats_e3_publish_qualification_zero_wrappers() { :; }
cats_e3_qualification_terminalize() { qualification_terminalized=true; }
cats_e3_close_on_exit
"#;
    let invoke = |mode: &str| {
        Command::new("bash")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").expect("test PATH"))
            .args(["-c", script, "runtime-cutover-emergency-before-g3"])
            .arg(fixture.root.join("deploy/metal/runtime-cutover-e2e.sh"))
            .arg(&trace)
            .arg(&state)
            .arg(mode)
            .output()
            .expect("run emergency decision crash fixture")
    };

    let killed = invoke("kill");
    assert_eq!(
        killed.status.signal(),
        Some(9),
        "first process was not SIGKILLed: status={:?} stderr={}",
        killed.status,
        String::from_utf8_lossy(&killed.stderr)
    );
    assert_eq!(
        fs::read_to_string(state.join("qualification-close-decision.v1.json")).unwrap(),
        "emergency_close\n",
        "TERM/red authority must be durable before long G3 cleanup"
    );

    let resumed = invoke("resume");
    assert_success(&resumed);
    assert_eq!(
        fs::read_to_string(trace).unwrap(),
        concat!(
            "decision:emergency_close\n",
            "g3:kill\n",
            "decision:emergency_close\n",
            "g3:resume\n",
            "close:emergency_close\n"
        )
    );
}

#[test]
fn runner_does_not_close_until_forward_g3_cleanup_succeeds_on_reentry() {
    let fixture = Fixture::new();
    let trace = fixture
        ._temp
        .path()
        .join("runner-g3-failure-before-close.trace");
    let state = fixture
        ._temp
        .path()
        .join("runner-g3-failure-before-close.state");
    fs::create_dir(&state).expect("create G3 recovery state");
    let script = r#"
set -euo pipefail
source "$1"
trace=$2
state_directory=$3
mode=$4
decision=$state_directory/qualification-close-decision.v1.json
qualification_lifecycle_attempted=true
qualification_begin_applied=true
qualification_close_applied=false
qualification_close_forbidden=false
qualification_terminalized=false
qualification_close_kind=
if [[ -f $decision ]]; then
  qualification_close_kind=$(cat "$decision")
fi
cats_e3_persist_close_decision() {
  if [[ -f $decision ]]; then
    test "$(cat "$decision")" = "$1"
  else
    (umask 077; printf '%s\n' "$1" >"$decision")
    sync -f "$state_directory"
  fi
  printf 'decision:%s:%s\n' "$mode" "$1" >>"$trace"
}
cats_e3_forward_recover_g3_on_exit() {
  printf 'g3:%s\n' "$mode" >>"$trace"
  [[ $mode == resume ]]
}
cats_e3_qualification_close() {
  printf 'close:%s:%s\n' "$mode" "$1" >>"$trace"
  test "$mode" = resume
  test "$1" = emergency_close
  qualification_close_applied=true
}
cats_e3_qualification_product_inventory() { :; }
cats_e3_collect_final_inventory() { :; }
cats_e3_publish_qualification_zero_wrappers() { :; }
cats_e3_qualification_terminalize() { qualification_terminalized=true; }
cats_e3_close_on_exit
"#;
    let invoke = |mode: &str| {
        Command::new("bash")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").expect("test PATH"))
            .args(["-c", script, "runtime-cutover-g3-failure-before-close"])
            .arg(fixture.root.join("deploy/metal/runtime-cutover-e2e.sh"))
            .arg(&trace)
            .arg(&state)
            .arg(mode)
            .output()
            .expect("run G3 failure before close fixture")
    };

    let first = invoke("fail");
    assert!(
        !first.status.success(),
        "first G3 cleanup unexpectedly passed"
    );
    assert_eq!(
        fs::read_to_string(&trace).unwrap(),
        concat!("decision:fail:emergency_close\n", "g3:fail\n"),
        "a failed forward cleanup must have zero Qualification Close effects"
    );
    assert_eq!(
        fs::read_to_string(state.join("qualification-close-decision.v1.json")).unwrap(),
        "emergency_close\n"
    );

    let resumed = invoke("resume");
    assert_success(&resumed);
    assert_eq!(
        fs::read_to_string(trace).unwrap(),
        concat!(
            "decision:fail:emergency_close\n",
            "g3:fail\n",
            "decision:resume:emergency_close\n",
            "g3:resume\n",
            "close:resume:emergency_close\n"
        )
    );
}

#[test]
fn runner_pins_private_directories_and_two_runners_reject_a_writable_grandparent() {
    let fixture = Fixture::new();
    let fixture_temp = fs::canonicalize(fixture._temp.path()).expect("canonical fixture root");
    let safe = fixture_temp.join("safe-pinned-parent");
    fs::create_dir(&safe).expect("create safe pinned state");
    fs::set_permissions(&safe, fs::Permissions::from_mode(0o700))
        .expect("protect safe pinned state");
    let positive = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args([
            "-c",
            concat!(
                "set -euo pipefail; source \"$1\"; ",
                "cats_e3_pin_private_directory \"$2\" state_fd state_alias private; ",
                "cats_e3_open_pinned_state_lock \"$state_fd\" \"$state_alias\" lock_fd; ",
                "cats_e3_create_pinned_output_directory \"$state_fd\" \"$state_alias\" ",
                "output output_fd output_alias; ",
                "printf '%s\\n' pinned >\"$output_alias/marker\"; ",
                "cats_e3_private_state_subdirectory \"$2/child\"",
            ),
            "runtime-cutover-safe-private-directory",
        ])
        .arg(fixture.root.join("deploy/metal/runtime-cutover-e2e.sh"))
        .arg(&safe)
        .output()
        .expect("run safe directory calibration");
    assert_success(&positive);
    assert_eq!(
        fs::read_to_string(safe.join("output/marker")).unwrap(),
        "pinned\n"
    );

    let unsafe_grandparent = fixture_temp.join("writable-grandparent");
    fs::create_dir(&unsafe_grandparent).expect("create writable grandparent");
    fs::set_permissions(&unsafe_grandparent, fs::Permissions::from_mode(0o777))
        .expect("make grandparent writable");
    let checked = unsafe_grandparent.join("checked");
    let alternate = unsafe_grandparent.join("alternate");
    fs::create_dir(&checked).expect("create checked inode A");
    fs::create_dir(&alternate).expect("create alternate inode B");
    for path in [&checked, &alternate] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("protect swappable state parent");
    }
    let result_a = fixture._temp.path().join("runner-a.result");
    let result_b = fixture._temp.path().join("runner-b.result");
    let gate_a = fixture._temp.path().join("runner-a.go");
    let gate_b = fixture._temp.path().join("runner-b.go");
    let release = fixture._temp.path().join("runners.release");
    let script = r#"
set -euo pipefail
source "$1"
directory=$2/state
result=$3
gate=$4
release=$5
runner=$6
while [[ ! -e $gate ]]; do sleep 0.01; done
if cats_e3_private_state_subdirectory "$directory"; then
  lock_ready=$result.locked
  python3 - "$directory/.runtime-cutover.lock" "$lock_ready" "$release" <<'PY' &
import fcntl
import os
import pathlib
import sys
import time
lock_path, ready_path, release_path = map(pathlib.Path, sys.argv[1:])
descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
ready_path.write_text("locked\n", encoding="ascii")
while not release_path.exists():
    time.sleep(0.01)
os.close(descriptor)
PY
  lock_pid=$!
  while [[ ! -e $lock_ready ]]; do sleep 0.01; done
  source_file=$directory/$runner.source
  printf '{"runner":"%s"}\n' "$runner" >"$source_file"
  chmod 0600 "$source_file"
  cats_e3_bind_persistent_state "$directory" "$source_file" runtime-state.json
  rm -f "$source_file"
  identity=$(python3 - "$directory" <<'PY'
import os
import sys
value = os.stat(sys.argv[1], follow_symlinks=False)
print(f"{value.st_dev}:{value.st_ino}")
PY
  )
  printf 'accepted:%s\n' "$identity" >"$result"
  while [[ ! -e $release ]]; do sleep 0.01; done
  wait "$lock_pid"
else
  printf '%s\n' rejected >"$result"
fi
"#;
    let run = |result: &Path, gate: &Path, runner: &str| {
        Command::new("bash")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").expect("test PATH"))
            .args(["-c", script, "runtime-cutover-writable-grandparent"])
            .arg(fixture.root.join("deploy/metal/runtime-cutover-e2e.sh"))
            .arg(&checked)
            .arg(result)
            .arg(gate)
            .arg(&release)
            .arg(runner)
            .spawn()
            .expect("spawn writable-grandparent fixture")
    };

    let child_a = run(&result_a, &gate_a, "runner-a");
    let child_b = run(&result_b, &gate_b, "runner-b");
    fs::write(&gate_a, b"go\n").expect("release runner A");
    for _ in 0..500 {
        if result_a.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(result_a.exists(), "runner A did not reach the barrier");
    let held_a = unsafe_grandparent.join("held-a");
    fs::rename(&checked, &held_a).expect("move checked inode A aside");
    fs::rename(&alternate, &checked).expect("install checked inode B");
    fs::write(&gate_b, b"go\n").expect("release runner B");
    for _ in 0..500 {
        if result_b.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(result_b.exists(), "runner B did not reach the barrier");
    fs::write(&release, b"release\n").expect("release both runners");
    let output_a = child_a.wait_with_output().expect("wait for runner A");
    let output_b = child_b.wait_with_output().expect("wait for runner B");
    assert_success(&output_a);
    assert_success(&output_b);
    let observed_a = fs::read_to_string(&result_a).unwrap();
    let observed_b = fs::read_to_string(&result_b).unwrap();
    assert_eq!(
        (observed_a.as_str(), observed_b.as_str()),
        ("rejected\n", "rejected\n"),
        "two runners acquired the same lexical state through different inodes: \
         runner-a={observed_a:?} runner-b={observed_b:?}; \
         marker-a={} marker-b={}",
        held_a.join("state/runtime-state.json").exists(),
        checked.join("state/runtime-state.json").exists(),
    );
}

#[test]
fn runner_adopts_a_same_inode_runtime_state_temp_after_link_crash_before_strict_read() {
    let fixture = Fixture::new();
    let root = fs::canonicalize(fixture._temp.path()).expect("canonical fixture root");
    let state = root.join("nlink-runtime-state");
    let prefix = state.join("case-prefix");
    let cases = state.join("cases");
    let work = root.join("nlink-runtime-work");
    for directory in [&state, &prefix, &cases, &work] {
        fs::create_dir(directory).expect("create nlink recovery directory");
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("protect nlink recovery directory");
    }
    let script = r#"
set -euo pipefail
source "$1"
state_directory=$2
persistent_case_prefix_dir=$state_directory/case-prefix
persistent_cases_dir=$state_directory/cases
persistent_runtime_state=$state_directory/runtime-state.json
work=$3
catalog=$4
catalog_work=$work/catalog.jsonl
results_work=$work/results.jsonl
evidence_work=$work/evidence.jsonl
journal_work=$work/journal.txt
jq -S -c '.framework_required_evidence as $framework | .cases[] |
  .required_evidence = (.required_evidence + $framework)' "$catalog" >"$catalog_work"
: >"$results_work"
: >"$evidence_work"
: >"$journal_work"
run_id=fixture-nlink-runtime
block_path=kernel-nbd
workspace_id=fixture-workspace
exact_commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
qualification_catalog_authority_sha256=$(sha256sum "$catalog" | awk '{print $1}')
printf '%s\n' '{}' >"$state_directory/qualification-state-binding.v1.json"
chmod 0600 "$state_directory/qualification-state-binding.v1.json"
ln "$state_directory/qualification-state-binding.v1.json" \
  "$state_directory/.qualification-state-binding.v1.json.crash-after-link"
jq -S -c -n --arg run_id "$run_id" --arg block_path "$block_path" \
  --arg exact_commit "$exact_commit" \
  '{block_path:$block_path,cat_id:null,exact_commit:$exact_commit,run_id:$run_id,version:1}' \
  >"$persistent_runtime_state"
chmod 0600 "$persistent_runtime_state"
ln "$persistent_runtime_state" "$state_directory/.runtime-state.json.crash-after-link"
printf '%s\n' '{}' >"$state_directory/qualification-close-decision.v1.json"
chmod 0600 "$state_directory/qualification-close-decision.v1.json"
ln "$state_directory/qualification-close-decision.v1.json" \
  "$state_directory/.qualification-close-decision.v1.json.crash-after-link"
test "$(python3 - "$persistent_runtime_state" <<'PY'
import os
import sys
print(os.stat(sys.argv[1], follow_symlinks=False).st_nlink)
PY
)" = 2
cats_e3_recover_persistent_state_link "$state_directory" \
  qualification-close-decision.v1.json
test "$(cats_e3_restore_case_prefix)" = 0
test ! -e "$state_directory/.qualification-state-binding.v1.json.crash-after-link"
test ! -e "$state_directory/.runtime-state.json.crash-after-link"
test ! -e "$state_directory/.qualification-close-decision.v1.json.crash-after-link"
for canonical in qualification-state-binding.v1.json runtime-state.json \
  qualification-close-decision.v1.json; do
  test "$(python3 - "$state_directory/$canonical" <<'PY'
import os
import sys
print(os.stat(sys.argv[1], follow_symlinks=False).st_nlink)
PY
)" = 1
done
ln "$state_directory/qualification-close-decision.v1.json" \
  "$state_directory/.qualification-close-decision.v1.json.ambiguous-a"
ln "$state_directory/qualification-close-decision.v1.json" \
  "$state_directory/.qualification-close-decision.v1.json.ambiguous-b"
! cats_e3_recover_persistent_state_link "$state_directory" \
  qualification-close-decision.v1.json
test -e "$state_directory/.qualification-close-decision.v1.json.ambiguous-a"
test -e "$state_directory/.qualification-close-decision.v1.json.ambiguous-b"
rm "$state_directory/.qualification-close-decision.v1.json.ambiguous-a" \
  "$state_directory/.qualification-close-decision.v1.json.ambiguous-b"
test "$(python3 - "$persistent_runtime_state" <<'PY'
import os
import sys
print(os.stat(sys.argv[1], follow_symlinks=False).st_nlink)
PY
)" = 1
"#;
    let output = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("test PATH"))
        .args(["-c", script, "runtime-cutover-nlink-runtime"])
        .arg(fixture.root.join("deploy/metal/runtime-cutover-e2e.sh"))
        .arg(&state)
        .arg(&work)
        .arg(
            fixture
                .root
                .join("deploy/metal/runtime-cutover-e2e-catalog.v1.json"),
        )
        .output()
        .expect("run runtime-state nlink recovery fixture");
    assert_success(&output);
}

#[test]
fn cat_create_partial_stdout_replays_the_durable_cli_journal_in_a_new_process() {
    let fixture = Fixture::new();
    let root = fs::canonicalize(fixture._temp.path()).expect("canonical fixture root");
    let token = root.join("control-token");
    fs::write(&token, b"fixture-token\n").expect("write token");
    let fake_cats = root.join("fake-cats");
    fs::write(
        &fake_cats,
        r#"#!/usr/bin/env bash
set -euo pipefail
journal=$CATS_CONFIG_DIR/fake-cat-create.pending
arguments=" $* "
if [[ $arguments == *" create "* ]]; then
  existing_only=false
  [[ $arguments != *" --existing-pending-only "* ]] || existing_only=true
  if [[ $existing_only == true && ! -e $journal ]]; then
    printf '%s\n' existing-absent >>"$FAKE_CREATE_TRACE"
    sync -f "$FAKE_CREATE_TRACE"
    printf '%s\n' '{"pending_cat_create":false}'
    exit 0
  fi
  if [[ $existing_only == true ]]; then
    printf '%s\n' existing >>"$FAKE_CREATE_TRACE"
  else
    printf '%s\n' normal >>"$FAKE_CREATE_TRACE"
  fi
  sync -f "$FAKE_CREATE_TRACE"
  if [[ ! -e $journal ]]; then
    printf '%s\n' fixture-request >"$journal"
    sync -f "$CATS_CONFIG_DIR"
  fi
  case "${FAKE_CREATE_CRASH_POINT:-none}" in
    before-response)
      kill -KILL "$CATS_E3_FIXTURE_SCENARIO_PID"
      exit 99
      ;;
    during-response)
      printf '%s' '{"cat_id":"cat-fixture"'
      kill -KILL "$CATS_E3_FIXTURE_SCENARIO_PID"
      exit 99
      ;;
  esac
  printf '%s\n' '{"cat_id":"cat-fixture","operation_id":"op-fixture"}'
  rm -f "$journal"
  sync -f "$CATS_CONFIG_DIR"
  exit 0
fi
if [[ $arguments == *" operation wait "* ]]; then
  printf '%s\n' '{"operation_id":"op-fixture","workspace_id":"workspace-fixture","phase":"succeeded","target":"running","terminal":{"kind":"succeeded","result":{"observed_target":"running"}}}'
  exit 0
fi
if [[ $arguments == *" get cat-fixture "* ]]; then
  printf '%s\n' '{"id":"cat-fixture","desired":{"target":"running"},"observed":{"stable_state":"running","conditions":["ready"]}}'
  exit 0
fi
exit 97
"#,
    )
    .expect("write fake Cats CLI");
    fs::set_permissions(&fake_cats, fs::Permissions::from_mode(0o755))
        .expect("make fake Cats CLI executable");
    let fake_probe = root.join("fake-runtime-e3-probe");
    fs::write(
        &fake_probe,
        concat!(
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            "printf '%s\\n' '{\"version\":1,\"cat_id\":\"cat-fixture\",",
            "\"node_id\":\"node-fixture\",\"runtime_incarnation\":\"inc-fixture\",",
            "\"root_block_frontend\":\"kernel-nbd\"}'\n",
        ),
    )
    .expect("write fake runtime probe");
    fs::set_permissions(&fake_probe, fs::Permissions::from_mode(0o755))
        .expect("make fake runtime probe executable");
    let fake_bin = root.join("fake-coreutils");
    fs::create_dir(&fake_bin).expect("create fake coreutils directory");
    let fake_stat = fake_bin.join("stat");
    fs::write(
        &fake_stat,
        r#"#!/usr/bin/env bash
set -euo pipefail
# GNU stat (Linux) takes -c directly; only the BSD stat behind macOS needs
# the flag translation below.
if [[ ${1:-} == -c ]] && /usr/bin/stat -c '%h' /dev/null >/dev/null 2>&1; then
  exec /usr/bin/stat "$@"
fi
if [[ ${1:-} == -c ]]; then
  format=$2
  shift 2
  case "$format" in
    %h) exec /usr/bin/stat -f '%l' "$@" ;;
    %a) exec /usr/bin/stat -f '%Lp' "$@" ;;
  esac
fi
exec /usr/bin/stat "$@"
"#,
    )
    .expect("write portable stat fixture");
    fs::set_permissions(&fake_stat, fs::Permissions::from_mode(0o755))
        .expect("make stat fixture executable");
    let fixture_path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").expect("test PATH")
    );

    // The fake CLI needs the scenario PID, so launch through one tiny process
    // wrapper that exports its own PID before exec'ing the production driver.
    let wrapper = root.join("scenario-wrapper.sh");
    fs::write(
        &wrapper,
        "#!/usr/bin/env bash\nexport CATS_E3_FIXTURE_SCENARIO_PID=$$\nexec \"$@\"\n",
    )
    .expect("write scenario wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755))
        .expect("make scenario wrapper executable");

    let driver = fixture
        .root
        .join("deploy/metal/runtime-cutover-v2-scenarios.sh");
    let invoke = |case_dir: &Path,
                  cli_state: &Path,
                  runtime_state: &Path,
                  fake_crash_point: &str,
                  crash_before_runtime_state: bool| {
        let mut command = Command::new(&wrapper);
        command
            .env_clear()
            .env("PATH", &fixture_path)
            .env("CATS_CONFIG_DIR", cli_state)
            .env("CATS_E3_TOKEN_FILE", &token)
            .env("CATS_E3_BINARY_CATS", &fake_cats)
            .env("CATS_E3_BINARY_RUNTIME_E3_PROBE", &fake_probe)
            .env("CATS_E3_CONTROL_ORIGIN", "https://control.example")
            .env("CATS_E3_WORKSPACE_ID", "workspace-fixture")
            .env("CATS_E3_QUALIFICATION_NODE_ID", "node-fixture")
            .env("CATS_E3_CAT_NAME", "fixture-cat")
            .env(
                "CATS_E3_BOOT_IMAGE_DIGEST",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .env(
                "CATS_E3_EXACT_COMMIT",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .env("CATS_E3_RUN_ID", "fixture-create-recovery")
            .env("CATS_E3_RUNTIME_STATE", runtime_state)
            .env("FAKE_CREATE_CRASH_POINT", fake_crash_point)
            .env("FAKE_CREATE_TRACE", cli_state.join("create.trace"))
            .arg(&driver)
            .args(["run", "cat-create-running", "kernel-nbd"])
            .arg(case_dir);
        if crash_before_runtime_state {
            command
                .env("CATS_E3_FIXTURE_MODE", "enabled")
                .env(
                    "CATS_E3_FIXTURE_CAT_CREATE_CRASH_POINT",
                    "before-runtime-state",
                )
                .env(
                    "CATS_E3_FIXTURE_KILL_ONCE_FILE",
                    cli_state.join("before-runtime-state.kill-once"),
                );
        }
        command
    };

    for (label, fake_crash_point, crash_before_runtime_state, expected_replay) in [
        ("before-response", "before-response", false, "existing"),
        ("during-response", "during-response", false, "existing"),
        ("before-runtime-state", "none", true, "existing-absent"),
    ] {
        let case_dir = root.join(format!("cat-create-response-{label}"));
        let cli_state = root.join(format!("cat-create-cli-{label}"));
        fs::create_dir(&case_dir).expect("create Cat-create case directory");
        fs::create_dir(&cli_state).expect("create fake CLI state directory");
        for directory in [&case_dir, &cli_state] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("protect Cat-create fixture directory");
        }
        let runtime_state = root.join(format!("cat-create-runtime-{label}.json"));
        fs::write(
            &runtime_state,
            concat!(
                "{\"block_path\":\"kernel-nbd\",\"cat_id\":null,",
                "\"exact_commit\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
                "\"run_id\":\"fixture-create-recovery\",\"version\":1}\n"
            ),
        )
        .expect("write initial runtime state");
        fs::set_permissions(&runtime_state, fs::Permissions::from_mode(0o600))
            .expect("protect runtime state");

        let killed = invoke(
            &case_dir,
            &cli_state,
            &runtime_state,
            fake_crash_point,
            crash_before_runtime_state,
        )
        .output()
        .expect("run interrupted Cat-create process");
        assert_eq!(
            killed.status.signal(),
            Some(9),
            "{label} Cat-create fixture was not killed: status={:?} stderr={}",
            killed.status,
            String::from_utf8_lossy(&killed.stderr)
        );

        let response_temps: Vec<_> = fs::read_dir(&case_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".create-response.json.")
            })
            .collect();
        if crash_before_runtime_state {
            assert!(response_temps.is_empty());
            assert!(case_dir.join("create-response.json").exists());
        } else {
            assert_eq!(response_temps.len(), 1, "{label} response temp count");
            let interrupted_bytes = fs::read(&response_temps[0]).unwrap();
            if fake_crash_point == "before-response" {
                assert!(interrupted_bytes.is_empty());
            } else {
                assert_eq!(interrupted_bytes, br#"{"cat_id":"cat-fixture""#);
            }
            assert!(!case_dir.join("create-response.json").exists());
            assert!(cli_state.join("fake-cat-create.pending").exists());
        }
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&runtime_state).unwrap())
                .unwrap()["cat_id"],
            serde_json::Value::Null,
            "{label} published runtime Cat state before its crash point"
        );

        let resumed = invoke(
            &case_dir,
            &cli_state,
            &runtime_state,
            "none",
            crash_before_runtime_state,
        )
        .output()
        .expect("resume Cat-create process");
        assert_success(&resumed);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(case_dir.join("create-response.json")).unwrap()
            )
            .unwrap(),
            serde_json::json!({"cat_id":"cat-fixture","operation_id":"op-fixture"})
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&runtime_state).unwrap())
                .unwrap()["cat_id"],
            "cat-fixture"
        );
        assert!(!case_dir.join("create-response.pending.json").exists());
        assert!(!cli_state.join("fake-cat-create.pending").exists());
        let response_temp_residue: Vec<_> = fs::read_dir(&case_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".create-response"))
            .collect();
        assert!(
            response_temp_residue.is_empty(),
            "{label} left response temps: {response_temp_residue:?}"
        );
        assert_eq!(
            fs::read_to_string(cli_state.join("create.trace"))
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["normal", expected_replay],
            "{label} did not use exactly one normal create plus one journal resolution"
        );
    }
}

#[test]
fn runtime_cutover_runner_sigkill_reentry_has_no_persistent_secret_residue() {
    const SECRET_CANARIES: [&str; 3] = [
        "fixture-production-cutover-operator-key-must-not-survive",
        "fixture-control-token-must-not-survive-sigkill",
        "fixture-route-rotation-operator-key-must-not-survive",
    ];
    let fixture = Fixture::new();
    let harness = fixture._temp.path().join("runner-reentry-harness.sh");
    let trace = fixture._temp.path().join("runner-reentry.trace");
    let state = fixture._temp.path().join("runner-reentry-state");
    fs::create_dir(&state).expect("create reentry state");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("protect reentry state");
    let state = fs::canonicalize(state).expect("canonical reentry state");
    let volatile_root = fixture._temp.path().join("runner-reentry-volatile");
    let secret_sources = fixture._temp.path().join("runner-reentry-secret-sources");
    for directory in [&volatile_root, &secret_sources] {
        fs::create_dir(directory).expect("create private reentry fixture directory");
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("protect private reentry fixture directory");
    }
    let volatile_root = fs::canonicalize(volatile_root).expect("canonical volatile fixture root");
    let secret_sources =
        fs::canonicalize(secret_sources).expect("canonical secret source fixture root");
    let operator_key = secret_sources.join("production-cutover-operator-key");
    let control_token = secret_sources.join("control-token");
    let route_key = secret_sources.join("route-rotation-operator-key");
    for (path, canary) in [
        (&operator_key, SECRET_CANARIES[0]),
        (&control_token, SECRET_CANARIES[1]),
        (&route_key, SECRET_CANARIES[2]),
    ] {
        fs::write(path, canary).expect("write original secret fixture input");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("protect original secret fixture input");
    }
    fs::write(
        &harness,
        r#"#!/usr/bin/env bash
set -euo pipefail
source "$1"
output_dir=$2
state_directory=$3
volatile_root=$4
trace=$5
scenario_driver=$6
filter=$7
catalog=$8
mode=$9
timeout_bin=${10}
operator_key_source=${11}
control_token_source=${12}
route_key_source=${13}
block_path=kernel-nbd
run_id=fixture-reentry
workspace_id=workspace-fixture
exact_commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
python3 - "$operator_key_source" "$control_token_source" "$route_key_source" <<'PY' || exit 86
import os
import stat
import sys
for path in sys.argv[1:]:
    value = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.geteuid()
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) != 0o600
    ):
        raise SystemExit(1)
PY
private_stage_name=invocation-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
cats_e3_prepare_private_stage "$volatile_root" "$private_stage_name" || exit 87
cp "$operator_key_source" "$cats_e3_private_stage/production-cutover-operator-key" || exit 88
chmod 0600 "$cats_e3_private_stage/production-cutover-operator-key"
cp "$control_token_source" "$cats_e3_private_stage/control-token" || exit 89
chmod 0600 "$cats_e3_private_stage/control-token"
cp "$route_key_source" "$cats_e3_private_stage/route-rotation-operator-key" || exit 90
chmod 0600 "$cats_e3_private_stage/route-rotation-operator-key"
if [[ $mode == kill ]]; then
  : >"$cats_e3_private_stage/.authorization.ABC123"
  printf 'authorization: Bearer fixture-control' \
    >"$cats_e3_private_stage/.authorization.DEF456"
  printf 'authorization: Bearer %s\n' "$(<"$control_token_source")" \
    >"$cats_e3_private_stage/.authorization.GHI789"
  chmod 0600 "$cats_e3_private_stage"/.authorization.*
fi
scratch=$output_dir/.scratch
mkdir -m 0700 "$output_dir" "$scratch"
results_work=$scratch/scenario-results.jsonl
journal_work=$scratch/component-journal-summary.txt
evidence_work=$scratch/case-evidence.jsonl
catalog_work=$scratch/scenario-catalog.jsonl
: >"$results_work"
: >"$journal_work"
: >"$evidence_work"
: >"$catalog_work"
case_ids=()
case_deadlines=()
case_cleanup_deadlines=()
case_expected_outcomes=()
case_required_evidence=()
while IFS= read -r case_record; do
  case_ids+=("$(jq -r '.case_id' <<<"$case_record")")
  case_deadlines+=("$(jq -r '.deadline_seconds' <<<"$case_record")")
  case_cleanup_deadlines+=("$(jq -r '.cleanup_deadline_seconds' <<<"$case_record")")
  case_expected_outcomes+=("$(jq -c '.expected_outcome' <<<"$case_record")")
  case_required_evidence+=("$(jq -c '.required_evidence' <<<"$case_record")")
  printf '%s\n' "$case_record" >>"$catalog_work"
done < <(jq -S -c '
  .framework_required_evidence as $framework
  | .cases[:3][]
  | .required_evidence = (.required_evidence + $framework)' "$catalog")
qualification_catalog_authority_sha256=$(sha256sum "$catalog" | awk '{print $1}')
persistent_cases_dir=$state_directory/cases
persistent_case_prefix_dir=$state_directory/case-prefix
persistent_runtime_state=$state_directory/runtime-state.json
cats_e3_private_state_subdirectory "$persistent_cases_dir"
cats_e3_private_state_subdirectory "$persistent_case_prefix_dir"
binding_source=$scratch/qualification-state-binding.v1.json
jq -S -c -n --arg run_id "$run_id" --arg workspace_id "$workspace_id" \
  '{kind:"cats.fixture-runner-binding.v1",run_id:$run_id,version:1,workspace_id:$workspace_id}' \
  >"$binding_source"
chmod 0600 "$binding_source"
cats_e3_bind_persistent_state "$state_directory" "$binding_source"
runtime_source=$scratch/runtime-state.initial.json
jq -S -c -n --arg exact_commit "$exact_commit" --arg block_path "$block_path" \
  --arg run_id "$run_id" \
  '{block_path:$block_path,cat_id:null,exact_commit:$exact_commit,run_id:$run_id,version:1}' \
  >"$runtime_source"
chmod 0600 "$runtime_source"
if [[ ! -e $persistent_runtime_state ]]; then
  cats_e3_bind_persistent_state "$state_directory" "$runtime_source" runtime-state.json
fi
first_incomplete_case_index=$(cats_e3_restore_case_prefix)
export CATS_E3_FIXTURE_MODE=enabled
export CATS_E3_FIXTURE_TRACE=$trace
export CATS_E3_FIXTURE_CATALOG=$catalog
export CATS_E3_FIXTURE_RUNTIME_CAT_ID=cat-fixture-reentry
export CATS_E3_RUNTIME_STATE=$persistent_runtime_state
if [[ $mode == kill ]]; then
  export CATS_E3_FIXTURE_SIGKILL_CASE=cat-create-running
  export CATS_E3_FIXTURE_RUNNER_PID=$$
  export CATS_E3_FIXTURE_KILL_ONCE_FILE=$state_directory/kill-once
fi
cats_e3_run_cases_post_preflight product
printf '%s\n' "$first_incomplete_case_index" >"$output_dir/first-incomplete"
"#,
    )
    .expect("write reentry harness");
    fs::set_permissions(&harness, fs::Permissions::from_mode(0o755))
        .expect("make reentry harness executable");

    let invoke = |mode: &str, output: &Path| {
        Command::new("bash")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").expect("test PATH"))
            .env("CATS_E3_FIXTURE_TIMEOUT_TRACE", &fixture.timeout_trace)
            .arg(&harness)
            .arg(fixture.root.join("deploy/metal/runtime-cutover-e2e.sh"))
            .arg(output)
            .arg(&state)
            .arg(&volatile_root)
            .arg(&trace)
            .arg(
                fixture
                    .root
                    .join("deploy/metal/tests/runtime-cutover-e2e-scenario-fixture.sh"),
            )
            .arg(
                fixture
                    .root
                    .join("deploy/metal/runtime-cutover-evidence-filter.py"),
            )
            .arg(
                fixture
                    .root
                    .join("deploy/metal/runtime-cutover-e2e-catalog.v1.json"),
            )
            .arg(mode)
            .arg(&fixture.timeout)
            .arg(&operator_key)
            .arg(&control_token)
            .arg(&route_key)
            .output()
            .expect("run cross-process reentry fixture")
    };

    let first_output = fixture.output_dir("runner-reentry-first");
    let killed = invoke("kill", &first_output);
    assert_eq!(
        killed.status.signal(),
        Some(9),
        "first process was not SIGKILLed: status={:?} stderr={}",
        killed.status,
        String::from_utf8_lossy(&killed.stderr)
    );
    assert!(state
        .join("case-prefix/00-control-startup-schema.v1.json")
        .is_file());
    assert!(state
        .join("case-prefix/01-node-registration-full-inventory.v1.json")
        .is_file());
    assert!(!state
        .join("case-prefix/02-cat-create-running.v1.json")
        .exists());
    let runtime_state: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("runtime-state.json")).unwrap()).unwrap();
    assert_eq!(runtime_state["cat_id"], "cat-fixture-reentry");
    assert!(!state.join("invocation-secrets").exists());
    assert_tree_has_no_private_input_artifacts(&state, &SECRET_CANARIES);
    assert_tree_has_no_private_input_artifacts(&first_output, &SECRET_CANARIES);
    let volatile_stage = volatile_root
        .join("invocation-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assert!(volatile_stage.is_dir());
    for (name, canary) in [
        ("production-cutover-operator-key", SECRET_CANARIES[0]),
        ("control-token", SECRET_CANARIES[1]),
        ("route-rotation-operator-key", SECRET_CANARIES[2]),
    ] {
        assert_eq!(
            fs::read(volatile_stage.join(name)).unwrap(),
            canary.as_bytes()
        );
    }
    assert!(fs::read(volatile_stage.join(".authorization.ABC123"))
        .unwrap()
        .is_empty());
    assert_eq!(
        fs::read(volatile_stage.join(".authorization.DEF456")).unwrap(),
        b"authorization: Bearer fixture-control"
    );
    assert_eq!(
        fs::read(volatile_stage.join(".authorization.GHI789")).unwrap(),
        format!("authorization: Bearer {}\n", SECRET_CANARIES[1]).as_bytes()
    );

    fs::remove_file(&control_token).expect("remove one required original input before reentry");
    let missing_input_output = fixture.output_dir("runner-reentry-missing-secret-input");
    let missing_input = invoke("resume", &missing_input_output);
    assert_eq!(missing_input.status.code(), Some(86));
    assert!(!missing_input_output.exists());
    assert!(volatile_stage.is_dir());
    assert_tree_has_no_private_input_artifacts(&state, &SECRET_CANARIES);
    assert_tree_has_no_private_input_artifacts(&first_output, &SECRET_CANARIES);
    fs::write(&control_token, SECRET_CANARIES[1]).expect("restore required token input");
    fs::set_permissions(&control_token, fs::Permissions::from_mode(0o600))
        .expect("protect restored token input");

    let resumed_output = fixture.output_dir("runner-reentry-resumed");
    let resumed = invoke("resume", &resumed_output);
    assert_success(&resumed);
    assert!(!state.join("invocation-secrets").exists());
    assert_tree_has_no_private_input_artifacts(&first_output, &SECRET_CANARIES);
    assert_tree_has_no_private_input_artifacts(&resumed_output, &SECRET_CANARIES);
    assert_tree_has_no_private_input_artifacts(&state, &SECRET_CANARIES);
    assert_eq!(fs::read_dir(&volatile_root).unwrap().count(), 0);
    assert_eq!(
        fs::read_to_string(resumed_output.join("first-incomplete")).unwrap(),
        "3\n"
    );
    assert_eq!(
        fs::read_to_string(resumed_output.join("scenario-results.jsonl"))
            .unwrap()
            .lines()
            .count(),
        3
    );
    let events = fs::read_to_string(&trace).expect("read reentry trace");
    for (case_id, expected_runs) in [
        ("control-startup-schema", 1),
        ("node-registration-full-inventory", 1),
        ("cat-create-running", 2),
    ] {
        assert_eq!(
            events
                .lines()
                .filter(|line| *line == format!("run|{case_id}|kernel-nbd"))
                .count(),
            expected_runs,
            "wrong replay count for {case_id}: {events}"
        );
    }

    fs::write(
        state.join("runtime-state.json"),
        concat!(
            "{\"block_path\":\"kernel-nbd\",\"cat_id\":\"cat-foreign\",",
            "\"exact_commit\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
            "\"run_id\":\"fixture-reentry\",\"version\":1}\n"
        ),
    )
    .expect("inject foreign Cat identity");
    let rejected_output = fixture.output_dir("runner-reentry-foreign-cat");
    let rejected = invoke("resume", &rejected_output);
    assert!(
        !rejected.status.success(),
        "foreign Cat identity unexpectedly resumed: {}",
        String::from_utf8_lossy(&rejected.stdout)
    );
    assert!(!state.join("invocation-secrets").exists());
    assert_tree_has_no_private_input_artifacts(&rejected_output, &SECRET_CANARIES);
    assert_tree_has_no_private_input_artifacts(&state, &SECRET_CANARIES);
    assert_eq!(fs::read_dir(&volatile_root).unwrap().count(), 0);
}

#[test]
fn runtime_cutover_runner_redacts_and_bounds_diagnostics() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("redaction");
    let output = fixture.run_post_preflight(&output_dir, |command| {
        command
            .env("CATS_E3_FIXTURE_FAIL_CASE", "route-http-ws")
            .env("CATS_E3_FIXTURE_SECRETS", "true");
    });
    assert_success(&output);
    let journal = fs::read_to_string(output_dir.join("component-journal-summary.txt")).unwrap();
    for secret in [
        "fixture-token-must-not-survive",
        "fixture-password-must-not-survive",
        "fixture-private-key-must-not-survive",
    ] {
        assert!(!journal.contains(secret), "journal retained {secret}");
    }
    assert!(journal.contains("[REDACTED]"));
    assert!(journal.contains("[TRUNCATED:"));
    assert!(journal.len() <= 131_072);
}

#[test]
fn runtime_cutover_runner_rejects_sensitive_final_inventory() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("sensitive-inventory");
    let output = fixture.run_post_preflight(&output_dir, |command| {
        command.env("CATS_E3_FIXTURE_SENSITIVE_INVENTORY", "true");
    });
    assert_success(&output);
    assert_eq!(
        fs::read_to_string(output_dir.join("final-inventory.json")).unwrap(),
        "{\"status\":\"unavailable\"}\n"
    );
    let counts: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("case-counts.json")).unwrap()).unwrap();
    assert_eq!(counts["failed"], 1);
}

#[test]
fn runtime_cutover_runner_fails_closed_on_sensitive_restart_receipt_keys() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("sensitive-restart-receipt");
    let output = fixture.run_post_preflight(&output_dir, |command| {
        command.env(
            "CATS_E3_FIXTURE_SENSITIVE_RECEIPT_CASE",
            "agent-restart-adoption",
        );
    });
    assert_success(&output);
    let results = fs::read_to_string(output_dir.join("scenario-results.jsonl")).unwrap();
    let restart: serde_json::Value = results
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|row: &serde_json::Value| row["case_id"] == "agent-restart-adoption")
        .unwrap();
    assert_eq!(restart["status"], "failed");
    assert_eq!(restart["evidence_exit_code"], 125);
}

#[test]
fn runtime_cutover_runner_rejects_evidence_outside_the_catalog_union() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("extra-case-evidence");
    let output = fixture.run_post_preflight(&output_dir, |command| {
        command.env("CATS_E3_FIXTURE_EXTRA_EVIDENCE_CASE", "durable-write-flush");
    });
    assert_success(&output);
    let results = fs::read_to_string(output_dir.join("scenario-results.jsonl")).unwrap();
    let durable: serde_json::Value = results
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|row: &serde_json::Value| row["case_id"] == "durable-write-flush")
        .unwrap();
    assert_eq!(durable["status"], "failed");
    assert_eq!(durable["evidence_exit_code"], 125);
}

#[test]
fn runtime_cutover_runner_collects_only_the_three_route_rotation_terminal_files() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("route-rotation-wip-evidence");
    let output = fixture.run_post_preflight(&output_dir, |command| {
        command.env(
            "CATS_E3_FIXTURE_EXTRA_EVIDENCE_CASE",
            "route-v2-rotation-disable-live-delivery",
        );
    });
    assert_success(&output);

    let results = fs::read_to_string(output_dir.join("scenario-results.jsonl")).unwrap();
    let route: serde_json::Value = results
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|row: &serde_json::Value| row["case_id"] == "route-v2-rotation-disable-live-delivery")
        .unwrap();
    assert_eq!(route["status"], "passed");

    let evidence = fs::read_to_string(output_dir.join("case-evidence.jsonl")).unwrap();
    let route_files = evidence
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|row| row["case_id"] == "route-v2-rotation-disable-live-delivery")
        .map(|row| row["filename"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        route_files,
        [
            "route-v2-rotation-disable-live-delivery.receipt.json",
            "route-v2-rotation-disable-live-delivery.node-acks.json",
            "route-v2-rotation-disable-live-delivery.transcript.log",
            "cleanup-receipt.json",
        ]
    );
    assert!(!evidence.contains("extra-receipt.json"));
}

#[test]
fn runtime_cutover_runner_gives_only_route_rotation_a_long_cleanup_window() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("route-rotation-cleanup-deadline");
    let output = fixture.run_post_preflight(&output_dir, |_| {});
    assert_success(&output);
    let timeouts = fs::read_to_string(&fixture.timeout_trace).expect("read timeout trace");
    let route_lines = timeouts
        .lines()
        .filter(|line| line.contains(" route-v2-rotation-disable-live-delivery "))
        .collect::<Vec<_>>();
    assert!(route_lines.iter().any(
        |line| line.starts_with("--signal=TERM --kill-after=30 1800 ")
            && line.contains(" run route-v2-rotation-disable-live-delivery ")
    ));
    assert!(route_lines.iter().any(
        |line| line.starts_with("--signal=TERM --kill-after=30 1800 ")
            && line.contains(" cleanup route-v2-rotation-disable-live-delivery ")
    ));
    assert!(timeouts.lines().any(|line| {
        line.starts_with("--signal=TERM --kill-after=5 60 ")
            && line.contains(" cleanup durable-write-flush ")
    }));
}

#[test]
fn production_v2_driver_places_source_terminal_after_delete_and_preserves_typed_blocks() {
    let fixture = Fixture::new();
    let output_dir = fixture.output_dir("per-path-source-terminal");
    let output = fixture.run_post_preflight(&output_dir, |command| {
        command.env("CATS_E3_FIXTURE_BLOCK_CASES", "volume-init-matrix");
    });
    assert_success(&output);
    let results = fs::read_to_string(output_dir.join("scenario-results.jsonl")).unwrap();
    let rows = results
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), CASES.len());
    assert_eq!(
        rows.iter().filter(|row| row["status"] == "passed").count(),
        CASES.len() - 1
    );
    assert_eq!(
        rows.iter().filter(|row| row["status"] == "failed").count(),
        1
    );
    let restart = rows
        .iter()
        .find(|row| row["case_id"] == "agent-restart-adoption")
        .unwrap();
    assert_eq!(restart["status"], "passed");
    assert_eq!(restart["evidence_exit_code"], 0);
    let volume = rows
        .iter()
        .find(|row| row["case_id"] == "volume-init-matrix")
        .unwrap();
    assert_eq!(volume["run_exit_code"], 78);
    assert_eq!(volume["cleanup_exit_code"], 0);
    assert_eq!(volume["evidence_exit_code"], 0);
    assert_eq!(volume["observed_outcome"], "blocked");
    assert_eq!(volume["expected_outcome"]["kind"], "passed");
    assert_eq!(volume["outcome_matches"], false);
    let deletion_index = rows
        .iter()
        .position(|row| row["case_id"] == "delete-cleanup")
        .unwrap();
    let terminal_index = rows
        .iter()
        .position(|row| row["case_id"] == "usage-source-terminal-receipts")
        .unwrap();
    assert!(deletion_index < terminal_index);
    assert_eq!(rows[terminal_index]["status"], "passed");

    let runner = include_str!("../../../deploy/metal/runtime-cutover-e2e.sh");
    let driver = include_str!("../../../deploy/metal/runtime-cutover-v2-scenarios.sh");
    let catalog = include_str!("../../../deploy/metal/runtime-cutover-e2e-catalog.v1.json");
    for case_id in CASES {
        assert!(runner.contains(case_id));
        assert!(catalog.contains(case_id));
    }
    assert!(catalog.contains("post_block_path_cases"));
    assert!(catalog.contains("usage-target-terminal-receipt"));
    assert!(driver.contains("run_volume_init_matrix"));
    assert!(driver.contains("/actions/attach"));
    assert!(driver.contains("/actions/detach"));
    assert!(driver.contains("persistent-disk-receipt.json"));
    assert!(driver.contains("/v1/admin/usage/source-terminal/discover"));
    assert!(catalog.contains("usage-source-terminal-receipts.json"));
    assert!(driver.contains("CATS_E3_RUN_STARTED_AT_UNIX_MS"));
    assert!(!driver.contains("create-response.pending.json"));
    assert!(driver.contains(".create-response.json.XXXXXX"));
    assert!(driver.contains("--existing-pending-only"));
    assert!(driver.contains("${TOKEN_FILE%/*}/.authorization.XXXXXX"));
    assert!(!driver.contains("$CASE_DIR/.authorization.XXXXXX"));
    assert!(driver.contains("durable Cat identity has no adjacent create response"));
    assert!(driver.contains("os.fsync(directory_fd)"));
    assert!(
        driver.contains("Usage source terminal receipt directory is not protected resume state")
    );
    assert!(driver.contains(".source_epoch | type == \"string\" and length > 0"));
    assert!(!driver.contains("run_focused"));
    assert!(!driver.contains("before_agent_session:"));
    assert!(!driver.contains("after_agent_session:"));
    assert!(driver.contains("unset CATS_E3_TOKEN_FILE"));
    assert!(driver.contains("export -n TOKEN_FILE"));
    assert!(runner.contains("cats_e3_run_cases_post_preflight"));
    assert!(runner.contains("[[ $EUID -eq 0 ]]"));
}

#[test]
fn production_v2_rotation_recovery_keeps_a_durable_prefix_and_closed_evidence_set() {
    let driver = include_str!("../../../deploy/metal/runtime-cutover-v2-scenarios.sh");
    let run_start = driver
        .find("run_route_rotation_recovery() {")
        .expect("rotation recovery entry point");
    let run_end = driver[run_start..]
        .find("\nrun_restart() {")
        .map(|offset| run_start + offset)
        .expect("rotation recovery entry point boundary");
    let run = &driver[run_start..run_end];

    let initialize = run
        .find("initialize_rotation_journal")
        .expect("journal initialization");
    let validate_prefix = run
        .find("validate_rotation_phase_prefix")
        .expect("durable prefix validation");
    let discover_current = run
        .find("discover_rotation_resume_state")
        .expect("exact-current resume discovery");
    assert!(initialize < validate_prefix && validate_prefix < discover_current);
    assert!(!run.contains(": >\"$ROTATION_JOURNAL/rotation-phase-receipts.json\""));
    assert!(driver.contains("revision == completed_revision"));
    assert!(driver.contains("revision == next_revision"));
    assert!(driver.contains(".desired_revision == ($old_revision + 1)"));
    assert!(driver.contains(".desired_revision == ($old_revision + 2)"));
    assert!(driver.contains("\"$ROTATION_JOURNAL\" \"fresh-endpoint-unbind-\""));
    assert!(driver.contains("\"$ROTATION_JOURNAL\" \"fresh-endpoint-bind-\""));
    assert!(driver.contains("run_probe public-route-closed"));
    assert!(driver.contains("curl_bin\" --disable"));
    let transport_start = driver
        .find("curl_secret_url() {")
        .expect("rotation HTTPS transport");
    let transport_end = driver[transport_start..]
        .find("\nrotation_json_request() {")
        .map(|offset| transport_start + offset)
        .expect("rotation HTTPS transport boundary");
    let transport = &driver[transport_start..transport_end];
    assert!(transport.contains("--tlsv1.3 --http1.1"));
    assert!(!transport.contains("--tlsv1.2"));
    assert!(driver.contains("in_flight_attempt = $attempt"));
    assert!(driver.contains("unknown_probe_reset"));
    assert!(driver.contains("three_consecutive_public_ingress_reachable_route_v2_closed"));
    assert!(driver.contains("rotation_mutation_started"));
    assert!(driver.contains("policy=forward_recovered_active_fresh_endpoint_for_agent_restart"));
    assert!(!driver.contains("signed_command_exact_json"));
    assert!(!driver.contains("signed_apply_receipt_exact_json"));
    let terminal_validation = shell_section(
        driver,
        "validate_rotation_terminal_evidence() {",
        "\nensure_rotation_baseline() {",
    );
    for binding in [
        ".authority_id == $authority",
        ".route_deployment_id == $deployment",
        ".rotation_operator_trust_sha256 == $trust",
        ".command_bundle_sha256 == $command_bundle_sha",
        ".recovery_transport_sha256 == $recovery_transport_sha",
        ".fresh_endpoint.old_endpoint.name == $endpoint_name",
        ".fresh_endpoint.fresh_endpoint.name == $fresh_name",
        ".expected_nodes == $expected_nodes",
        ".terminal_signing_authority.signer_revision == 8",
    ] {
        assert!(
            terminal_validation.contains(binding),
            "terminal fast-path omits current staged binding {binding}"
        );
    }
    for terminal in [
        "route-v2-rotation-disable-live-delivery.receipt.json",
        "route-v2-rotation-disable-live-delivery.node-acks.json",
        "route-v2-rotation-disable-live-delivery.transcript.log",
    ] {
        assert!(driver.contains(terminal));
    }
}

#[test]
fn route_rotation_empty_prefix_survives_init_sigkill_and_resume() {
    let driver = include_str!("../../../deploy/metal/runtime-cutover-v2-scenarios.sh");
    let production = shell_section(
        driver,
        "file_link_count() {",
        "\nrotation_require_budget() {",
    );
    let temp =
        tempfile::tempdir_in(fixture_scratch_base()).expect("Route rotation init crash fixture");
    let harness = temp.path().join("rotation-init-crash.sh");
    let case_dir = temp.path().join("case");
    fs::create_dir(&case_dir).expect("create Route rotation case");
    let preamble = r#"#!/usr/bin/env bash
set -euo pipefail
CASE_DIR=$1
readonly CASE_DIR
MODE=$2
readonly CASE_ID=route-v2-rotation-disable-live-delivery
readonly ROTATION_JOURNAL=$CASE_DIR/route-v2-rotation-journal.v1
ROTATION_INVOCATION_DEADLINE_UNIX_SECONDS=
CATS_E3_RUN_ID=fixture-run
CATS_E3_EXACT_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
fail() { printf 'fixture failure: %s\n' "$*" >&2; exit 64; }
stat() {
  if [[ ${1:-} == -c && ${2:-} == %a ]]; then
    python3 - "$3" <<'PY'
import os
import stat
import sys
print(format(stat.S_IMODE(os.stat(sys.argv[1], follow_symlinks=False).st_mode), "o"))
PY
    return
  fi
  command stat "$@"
}
"#;
    let dispatch = r#"
initialize_rotation_journal
if [[ $MODE == kill ]]; then
  kill -KILL $$
fi
jq -e 'type == "array" and length == 0' \
  "$ROTATION_JOURNAL/rotation-phase-receipts.json" >/dev/null
"#;
    fs::write(&harness, [preamble, production, dispatch].join("\n"))
        .expect("write Route rotation init crash harness");
    fs::set_permissions(&harness, fs::Permissions::from_mode(0o755))
        .expect("make Route rotation init crash harness executable");

    let killed = Command::new("bash")
        .arg(&harness)
        .arg(&case_dir)
        .arg("kill")
        .output()
        .expect("initialize then SIGKILL Route rotation journal");
    assert_eq!(killed.status.signal(), Some(9));
    assert_eq!(
        fs::read(case_dir.join("route-v2-rotation-journal.v1/rotation-phase-receipts.json"))
            .unwrap(),
        b"[]\n"
    );

    let resumed = Command::new("bash")
        .arg(&harness)
        .arg(&case_dir)
        .arg("resume")
        .output()
        .expect("resume Route rotation journal after SIGKILL");
    assert_success(&resumed);
}

fn shell_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("shell section start");
    let end = source[start..]
        .find(end)
        .map(|offset| start + offset)
        .expect("shell section end");
    &source[start..end]
}

#[test]
fn disabled_route_probe_crashes_never_promote_one_or_two_observations() {
    let driver = include_str!("../../../deploy/metal/runtime-cutover-v2-scenarios.sh");
    let production = shell_section(
        driver,
        "disabled_public_route_observation_is_exact() {",
        "\nrotation_disabled_fleet_is_exact() {",
    );
    let temp = tempfile::tempdir_in(fixture_scratch_base()).expect("disabled probe fixture");
    let harness = temp.path().join("disabled-probe-harness.sh");
    let preamble = r#"#!/usr/bin/env bash
set -euo pipefail
CASE_DIR=$1
readonly CASE_DIR
readonly ROTATION_JOURNAL=$CASE_DIR/route-v2-rotation-journal.v1
CATS_E3_RUN_ID=fixture-run
CATS_E3_PUBLIC_ORIGIN=https://fixture.example
CATS_E3_ENDPOINT_HOSTNAME=fixture.example
PROBE_SEQUENCE=$2
CRASH_AFTER_OBSERVATIONS=${CRASH_AFTER_OBSERVATIONS:-0}
mkdir -p "$ROTATION_JOURNAL"
chmod 0700 "$ROTATION_JOURNAL"
fail() { printf 'fixture failure: %s\n' "$*" >&2; exit 64; }
durable_case_file() { chmod 0600 "$1"; }
atomic_json_path() {
  local destination=$1 source=$2 temporary observations
  temporary=$(mktemp "${destination%/*}/.fixture-atomic.XXXXXX")
  jq -S -c . "$source" >"$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$destination"
  if [[ $destination == "$ROTATION_JOURNAL/disabled-public-route-probe-state.json" &&
        $CRASH_AFTER_OBSERVATIONS -gt 0 && ! -e $CASE_DIR/crash-fired ]]; then
    observations=$(jq -r '.observations | length' "$destination")
    if [[ $observations -eq $CRASH_AFTER_OBSERVATIONS ]]; then
      : >"$CASE_DIR/crash-fired"
      kill -KILL $$
    fi
  fi
}
publish_json_idempotent_path() { atomic_json_path "$1" "$2"; }
rotation_transcript() { :; }
rotation_require_budget() { :; }
run_probe() {
  local counter=$ROTATION_JOURNAL/probe-counter index outcome
  if [[ -e $counter ]]; then index=$(<"$counter"); else index=0; fi
  outcome=$(sed -n "$((index + 1))p" "$PROBE_SEQUENCE")
  printf '%s' "$((index + 1))" >"$counter"
  [[ $outcome == ok ]] || return 1
  printf '%s\n' '{"version":1,"kind":"route_v2_public_admission_closed_v1","origin":"https://fixture.example","path":"/e3/fixture-run","run_id":"fixture-run","tls_reachable":true,"http_status":503,"content_type":"text/plain","retry_after_seconds":1,"content_encoding_absent":true,"body_sha256":"sha256:3993919ba29fc397f3bbc6bf5d814e9caa9f184b557eb9c5fd7a59d45a2ac609","terminal_marker":"public_ingress_reachable_route_v2_closed"}'
}
"#;
    fs::write(
        &harness,
        [preamble, production, "prove_rotation_disable_observed\n"].join("\n"),
    )
    .expect("write disabled probe harness");

    let run = |case_dir: &Path, sequence: &Path, crash_after: Option<u8>| {
        let mut command = Command::new("bash");
        command.arg(&harness).arg(case_dir).arg(sequence);
        if let Some(value) = crash_after {
            command.env("CRASH_AFTER_OBSERVATIONS", value.to_string());
        }
        command.output().expect("run disabled probe harness")
    };
    for crash_after in [1, 2] {
        let case_dir = temp.path().join(format!("crash-{crash_after}"));
        fs::create_dir(&case_dir).unwrap();
        let sequence = case_dir.join("sequence");
        fs::write(&sequence, "ok\nok\nok\nok\n").unwrap();
        let crashed = run(&case_dir, &sequence, Some(crash_after));
        assert_eq!(crashed.status.signal(), Some(9));
        assert!(!case_dir
            .join("route-v2-rotation-journal.v1/disabled-public-route.json")
            .exists());
        let resumed = run(&case_dir, &sequence, None);
        assert!(
            resumed.status.success(),
            "resume failed: {}",
            String::from_utf8_lossy(&resumed.stderr)
        );
        let receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(case_dir.join("route-v2-rotation-journal.v1/disabled-public-route.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["observation_count"], 3);
        assert_eq!(receipt["observations"].as_array().unwrap().len(), 3);
    }

    let case_dir = temp.path().join("failure-resets-prefix");
    fs::create_dir(&case_dir).unwrap();
    let sequence = case_dir.join("sequence");
    fs::write(&sequence, "ok\nfailed\nok\nok\nok\n").unwrap();
    let completed = run(&case_dir, &sequence, None);
    assert!(completed.status.success());
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(case_dir.join("route-v2-rotation-journal.v1/disabled-public-route.json"))
            .unwrap(),
    )
    .unwrap();
    let attempts = receipt["observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["attempt_index"].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(attempts, vec![3, 4, 5]);
}

#[test]
fn rotation_resume_rejects_noncurrent_process_without_a_durable_adjacent_command() {
    let driver = include_str!("../../../deploy/metal/runtime-cutover-v2-scenarios.sh");
    let production = shell_section(
        driver,
        "rotation_incomplete_phase_has_pending_command() {",
        "\nappend_rotation_phase_receipt() {",
    );
    let temp = tempfile::tempdir().expect("rotation current fixture");
    let case_dir = temp.path().join("case");
    let journal = case_dir.join("route-v2-rotation-journal.v1");
    fs::create_dir_all(&journal).unwrap();
    let harness = temp.path().join("rotation-current-harness.sh");
    let preamble = r#"#!/usr/bin/env bash
set -euo pipefail
CASE_DIR=$1
readonly CASE_DIR
readonly ROTATION_JOURNAL=$CASE_DIR/route-v2-rotation-journal.v1
DISCOVERY=$2
BUNDLE=$3
CATS_E3_ROUTE_ROTATION_OPERATOR_AUTHORITY_ID=authority_fixture
CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID=deployment_fixture
CATS_E3_ROUTE_ROTATION_OPERATOR_TRUST_SHA256=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
CATS_E3_EXACT_COMMIT=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
fail() { printf 'fixture failure: %s\n' "$*" >&2; exit 64; }
required() { local value=${!1:-}; [[ -n $value ]] || exit 64; printf '%s' "$value"; }
rotation_input() { printf '%s' "$BUNDLE"; }
rotation_json_request() { cp "$DISCOVERY" "$3"; }
durable_case_file() { :; }
rotation_transcript() { :; }
"#;
    fs::write(
        &harness,
        [preamble, production, "discover_rotation_resume_state\n"].join("\n"),
    )
    .unwrap();
    let digest_b = format!("sha256:{}", "b".repeat(64));
    let digest_c = format!("sha256:{}", "c".repeat(64));
    let bundle = temp.path().join("bundle.json");
    fs::write(
        &bundle,
        serde_json::to_vec(&serde_json::json!({
            "commands": [
                {"signer_revision": 2, "ring_version": 2,
                 "exact_authority_command_json": serde_json::json!({
                     "successor": {"signer": {"state": "active", "active_kid": "kid_two"}}
                 }).to_string()},
                {"signer_revision": 6, "ring_version": 4,
                 "exact_authority_command_json": serde_json::json!({
                     "successor": {"signer": {"state": "disabled"}}
                 }).to_string()}
            ],
            "control_rollouts": [
                {"signer_revision": 2, "signer_reference_sha256": digest_b,
                 "public_key_ring_digest": digest_c},
                {"signer_revision": 6, "signer_reference_sha256": digest_b,
                 "public_key_ring_digest": digest_c}
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let discovery = temp.path().join("discovery.json");
    let prefix = journal.join("rotation-phase-receipts.json");
    let invoke = |value: serde_json::Value, count: usize| {
        fs::write(&discovery, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::write(
            &prefix,
            serde_json::to_vec(&vec![serde_json::json!({}); count]).unwrap(),
        )
        .unwrap();
        Command::new("bash")
            .arg(&harness)
            .arg(&case_dir)
            .arg(&discovery)
            .arg(&bundle)
            .output()
            .unwrap()
    };
    let current = |revision: u64,
                   ring_version: u64,
                   state: &str,
                   kid: Option<&str>,
                   database_current: bool,
                   process_ready: bool| {
        serde_json::json!({
            "authority_id":"authority_fixture","database_current":database_current,
            "loaded_active_kid":kid,"loaded_public_key_ring_digest":digest_c,
            "loaded_public_key_ring_version":ring_version,
            "loaded_signer_reference_sha256":digest_b,"loaded_signer_revision":revision,
            "loaded_signer_state":state,"process_ready":process_ready,
            "release_commit_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "rotation_operator_trust_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "route_deployment_id":"deployment_fixture","version":1
        })
    };

    let stale_initial = invoke(current(1, 1, "active", Some("kid_one"), false, false), 0);
    assert_eq!(
        stale_initial.status.code(),
        Some(64),
        "unexpected stale-initial result: {}",
        String::from_utf8_lossy(&stale_initial.stderr)
    );
    let stale_active = invoke(current(2, 2, "active", Some("kid_two"), false, false), 1);
    assert_eq!(
        stale_active.status.code(),
        Some(64),
        "unexpected stale-active result: {}",
        String::from_utf8_lossy(&stale_active.stderr)
    );
    assert!(
        invoke(current(2, 2, "active", Some("kid_two"), true, true), 1)
            .status
            .success()
    );
    assert!(invoke(current(6, 4, "disabled", None, true, false), 5)
        .status
        .success());
}

#[test]
fn rotation_replay_probes_never_overwrite_canonical_crash_artifacts() {
    let driver = include_str!("../../../deploy/metal/runtime-cutover-v2-scenarios.sh");
    let adoption = shell_section(
        driver,
        "file_link_count() {",
        "\ninitialize_rotation_journal() {",
    );
    let mutations = shell_section(driver, "operation_wait() {", "\nfleet_verify_to() {");
    let rotation = shell_section(
        driver,
        "sign_rotation_attempt() {",
        "\nwait_rotation_store_precondition() {",
    );
    let temp = tempfile::tempdir().expect("immutable replay fixture");
    let harness = temp.path().join("immutable-replay-harness.sh");
    let fake_cats = temp.path().join("fake-cats");
    fs::write(
        &fake_cats,
        "#!/usr/bin/env bash\nprintf '%s\\n' '{\"foreign\":true}'\n",
    )
    .unwrap();
    fs::set_permissions(&fake_cats, fs::Permissions::from_mode(0o755)).unwrap();
    let preamble = r#"#!/usr/bin/env bash
set -euo pipefail
CASE_DIR=$1
readonly CASE_DIR
MODE=$2
FAKE_CATS=$3
CRASH_AFTER_LINK=${CRASH_AFTER_LINK:-false}
readonly ROTATION_JOURNAL=$CASE_DIR/route-v2-rotation-journal.v1
CATS_E3_WORKSPACE_ID=workspace_fixture
CATS_E3_RUN_ID=run_fixture
mkdir -p "$ROTATION_JOURNAL"
chmod 0700 "$ROTATION_JOURNAL"
fail() { printf 'fixture failure: %s\n' "$*" >&2; exit 64; }
sync() { :; }
binary() { printf '%s' "$FAKE_CATS"; }
rotation_input() { printf '%s' /dev/null; }
rotation_transport_field() { printf '%s' https://rotation.fixture; }
rotation_transcript() { :; }
rotation_phase_revision() { printf '%s' 2; }
rotation_phase_ring_version() { printf '%s' 2; }
required() { local value=${!1:-}; [[ -n $value ]] || exit 64; printf '%s' "$value"; }
canonical_id() { :; }
control_origin() { printf '%s' https://control.fixture; }
sha256_wire() { printf 'sha256:%s' "$(sha256sum "$1" | awk '{print $1}')"; }
durable_case_file() { chmod 0600 "$1"; }
curl_secret_url() { local output=$3; printf '%s\n' '{"foreign":true}' >"$output"; printf '%s' 200; }
curl_json() { local output=$3; printf '%s\n' '{"foreign":true}' >"$output"; }
run_cats() { printf '%s\n' '{"foreign":true}'; }
"#;
    let dispatch = r#"
case "$MODE" in
  race)
    candidate=$CASE_DIR/race-candidate.json
    destination=$CASE_DIR/race-canonical.json
    foreign=$CASE_DIR/race-foreign.json
    printf '%s\n' '{"candidate":true}' >"$candidate"
    printf '%s\n' '{"foreign":true}' >"$foreign"
    ln() { cp "$foreign" "$2"; command ln "$@"; }
    adopt_case_file "$candidate" "$destination"
    ;;
  signing)
    pending=$ROTATION_JOURNAL/publish_overlap.attempt-1.command.json
    signing=$ROTATION_JOURNAL/publish_overlap.attempt-1.signing-receipt.json
    printf '%s\n' '{"payload":{"command_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}' >"$pending"
    printf '%s\n' '{"canonical":"signing"}' >"$signing"
    sign_rotation_attempt publish_overlap 1 "$pending" "$signing"
    ;;
  store)
    pending=$ROTATION_JOURNAL/publish_overlap.attempt-1.command.json
    response=$ROTATION_JOURNAL/publish_overlap.attempt-1.store-receipt.json
    printf '%s\n' '{"payload":{"command_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}' >"$pending"
    printf '%s\n' '{"canonical":"store"}' >"$response"
    post_rotation_attempt publish_overlap "$pending" "$response"
    ;;
  mutation)
    printf '%s\n' '{"canonical":"mutation"}' >"$ROTATION_JOURNAL/fixture-mutation-response.json"
    product_mutation POST /fixture fixture-key running '' "$ROTATION_JOURNAL" fixture-
    ;;
  operation)
    printf '%s\n' '{"canonical":"operation"}' >"$ROTATION_JOURNAL/fixture-operation-op_fixture.json"
    operation_wait op_fixture running "$ROTATION_JOURNAL" fixture-
    ;;
  journal-link-crash)
    candidate=$ROTATION_JOURNAL/journal-candidate.json
    destination=$ROTATION_JOURNAL/journal-canonical.json
    printf '%s\n' '{"candidate":"journal"}' >"$candidate"
    if [[ $CRASH_AFTER_LINK == true ]]; then
      rm() {
        if [[ $1 == -f && -e $destination && $2 -ef $destination ]]; then exit 99; fi
        command rm "$@"
      }
    fi
    adopt_rotation_file "$candidate" "$destination"
    ;;
  case-link-crash)
    candidate=$CASE_DIR/case-candidate.json
    destination=$CASE_DIR/case-canonical.json
    printf '%s\n' '{"candidate":"case"}' >"$candidate"
    if [[ $CRASH_AFTER_LINK == true ]]; then
      rm() {
        if [[ $1 == -f && -e $destination && $2 -ef $destination ]]; then exit 99; fi
        command rm "$@"
      }
    fi
    adopt_case_file "$candidate" "$destination"
    ;;
  *) exit 65 ;;
esac
"#;
    fs::write(
        &harness,
        [preamble, adoption, mutations, rotation, dispatch].join("\n"),
    )
    .unwrap();

    let cases = [
        ("race", "race-canonical.json", "{\"foreign\":true}\n"),
        (
            "signing",
            "route-v2-rotation-journal.v1/publish_overlap.attempt-1.signing-receipt.json",
            "{\"canonical\":\"signing\"}\n",
        ),
        (
            "store",
            "route-v2-rotation-journal.v1/publish_overlap.attempt-1.store-receipt.json",
            "{\"canonical\":\"store\"}\n",
        ),
        (
            "mutation",
            "route-v2-rotation-journal.v1/fixture-mutation-response.json",
            "{\"canonical\":\"mutation\"}\n",
        ),
        (
            "operation",
            "route-v2-rotation-journal.v1/fixture-operation-op_fixture.json",
            "{\"canonical\":\"operation\"}\n",
        ),
    ];
    for (mode, relative, original) in cases {
        let case_dir = temp.path().join(mode);
        fs::create_dir(&case_dir).unwrap();
        let output = Command::new("bash")
            .arg(&harness)
            .arg(&case_dir)
            .arg(mode)
            .arg(&fake_cats)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(64),
            "{mode} unexpectedly accepted a foreign replay: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(case_dir.join(relative)).unwrap(),
            original
        );
    }

    for (mode, relative, original) in [
        (
            "journal-link-crash",
            "route-v2-rotation-journal.v1/journal-canonical.json",
            "{\"candidate\":\"journal\"}\n",
        ),
        (
            "case-link-crash",
            "case-canonical.json",
            "{\"candidate\":\"case\"}\n",
        ),
    ] {
        let case_dir = temp.path().join(mode);
        fs::create_dir(&case_dir).unwrap();
        let crashed = Command::new("bash")
            .arg(&harness)
            .arg(&case_dir)
            .arg(mode)
            .arg(&fake_cats)
            .env("CRASH_AFTER_LINK", "true")
            .output()
            .unwrap();
        assert_eq!(crashed.status.code(), Some(99));
        let destination = case_dir.join(relative);
        assert_eq!(fs::metadata(&destination).unwrap().nlink(), 2);
        assert_eq!(fs::read_to_string(&destination).unwrap(), original);

        let recovered = Command::new("bash")
            .arg(&harness)
            .arg(&case_dir)
            .arg(mode)
            .arg(&fake_cats)
            .output()
            .unwrap();
        assert!(
            recovered.status.success(),
            "{mode} recovery failed: {}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        assert_eq!(fs::metadata(&destination).unwrap().nlink(), 1);
        assert_eq!(fs::read_to_string(&destination).unwrap(), original);
    }
}
