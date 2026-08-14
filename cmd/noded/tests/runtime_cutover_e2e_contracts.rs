use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
}

#[allow(dead_code)]
impl Fixture {
    fn new() -> Self {
        let root = workspace_root();
        let exact_commit = git_head(&root);
        let temp = tempfile::tempdir().expect("runtime cutover fixture");
        let build_receipt = temp.path().join("build-receipt.json");
        let release_manifest = temp.path().join("release-manifest.json");
        let installer_receipt = temp.path().join("installer-receipt.json");
        let binary = temp.path().join("cats-noded");
        let config = temp.path().join("cats-public.conf");
        let timeout = temp.path().join("timeout");
        let timeout_trace = temp.path().join("timeout-trace");
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
export CATS_E3_CONTROL_ORIGIN=https://wrong.example.test
export CATS_E3_WORKSPACE_ID=wrong-workspace
export CATS_E3_EXPECTED_NODES=wrong-node
export CATS_E3_QUALIFICATION_NODE_ID=wrong-node
cats_e3_clear_ambient
cats_e3_export_qualification_environment
test -z "${CATS_TOKEN:-}"
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

    let temp = tempfile::tempdir_in(workspace_root()).expect("private-key validation fixture");
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
    fn assert_tree_has_no_secret(path: &Path, secret: &[u8]) {
        for entry in fs::read_dir(path).expect("read retained evidence directory") {
            let entry = entry.expect("read retained evidence entry");
            if entry
                .file_type()
                .expect("read evidence entry type")
                .is_dir()
            {
                assert_tree_has_no_secret(&entry.path(), secret);
                continue;
            }
            let bytes = fs::read(entry.path()).expect("read retained evidence file");
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "retained evidence contains control token bytes"
            );
        }
    }
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
    let runner = fixture.root.join("deploy/metal/runtime-cutover-e2e.sh");
    let secret = "fixture-control-token-must-not-survive";
    let script = r#"
set -euo pipefail
source "$1"
mkdir -m 0700 "$2"
cats_e3_prepare_private_stage "$4"
printf '%s\n' "$cats_e3_private_stage" >"$2/private-stage-path"
printf '%s' "$3" >"$cats_e3_private_stage/control-token"
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
    let runner = fixture.root.join("deploy/metal/runtime-cutover-e2e.sh");
    let secret = "fixture-control-token-must-not-survive-term";
    let script = r#"
set -euo pipefail
source "$1"
mkdir -m 0700 "$2"
cats_e3_prepare_private_stage "$4"
printf '%s\n' "$cats_e3_private_stage" >"$2/private-stage-path"
printf '%s' "$3" >"$cats_e3_private_stage/control-token"
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
fn operator_e3_window_closes_and_verifies_every_early_failure_or_term() {
    let root = workspace_root();
    let library = root.join("deploy/metal/runtime-cutover-e3-window.sh");
    let fixture = root.join("deploy/metal/tests/runtime-cutover-e3-window-fixture.sh");
    let temp = tempfile::tempdir().expect("E3 window fixture");
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
    let initiated = runbook.find("\ningress_open_initiated=1\n").unwrap();
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
    assert!(driver.contains(".source_epoch | type == \"string\" and length > 0"));
    assert!(!driver.contains("run_focused"));
    assert!(!driver.contains("before_agent_session:"));
    assert!(!driver.contains("after_agent_session:"));
    assert!(driver.contains("unset CATS_E3_TOKEN_FILE"));
    assert!(driver.contains("export -n TOKEN_FILE"));
    assert!(runner.contains("cats_e3_run_cases_post_preflight"));
    assert!(runner.contains("[[ $EUID -eq 0 ]]"));
}
