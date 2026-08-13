use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CASES: [&str; 8] = [
    "control-startup-schema",
    "node-registration-full-inventory",
    "cat-create-running",
    "durable-write-flush",
    "route-http-ws",
    "agent-restart-adoption",
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
                sha256(&self.binary)
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
    assert!(journal.len() <= 8 * 16_384);
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
