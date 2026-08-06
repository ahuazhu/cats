use std::{fs, path::Path, process::Command};

use cats_rc_source_chain::{
    verify_source_chain, IntegrationKind, SourceChainRecord, VerificationContext,
};
use tempfile::TempDir;

const REQUIRED_CHECKS: &[&str] = &["CI"];

struct TestRepository {
    directory: TempDir,
    previous: String,
    candidate: String,
    diverged: String,
    wrong_head: String,
}

impl TestRepository {
    fn create() -> Self {
        let directory = tempfile::tempdir().expect("create temporary Git repository");
        git(directory.path(), &["init", "--initial-branch=main"]);
        git(directory.path(), &["config", "user.name", "Cats Test"]);
        git(
            directory.path(),
            &["config", "user.email", "cats-test@example.invalid"],
        );

        fs::write(directory.path().join("state"), "previous\n").expect("write previous tree");
        git(directory.path(), &["add", "state"]);
        git(directory.path(), &["commit", "-m", "previous"]);
        let previous = rev_parse(directory.path(), "HEAD");

        fs::write(directory.path().join("state"), "candidate\n").expect("write candidate tree");
        git(directory.path(), &["commit", "-am", "candidate"]);
        let candidate = rev_parse(directory.path(), "HEAD");
        git(
            directory.path(),
            &["branch", "rc/architecture-v2", &candidate],
        );

        git(directory.path(), &["checkout", "--detach", &previous]);
        fs::write(directory.path().join("state"), "diverged\n").expect("write diverged tree");
        git(directory.path(), &["commit", "-am", "diverged"]);
        let diverged = rev_parse(directory.path(), "HEAD");

        git(directory.path(), &["checkout", "--detach", &previous]);
        fs::write(directory.path().join("state"), "wrong head\n").expect("write wrong tree");
        git(directory.path(), &["commit", "-am", "wrong head"]);
        let wrong_head = rev_parse(directory.path(), "HEAD");
        git(directory.path(), &["checkout", "main"]);

        Self {
            directory,
            previous,
            candidate,
            diverged,
            wrong_head,
        }
    }

    fn record(&self, fixture: &str) -> Result<SourceChainRecord, serde_json::Error> {
        let source = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(fixture),
        )
        .expect("read source-chain fixture")
        .replace("__CONTROLLER__", &self.previous)
        .replace("__PREVIOUS__", &self.previous)
        .replace("__CANDIDATE__", &self.candidate)
        .replace("__DIVERGED__", &self.diverged)
        .replace("__WRONG_HEAD__", &self.wrong_head);
        serde_json::from_str(&source)
    }

    fn context(&self) -> VerificationContext<'_> {
        self.context_for(&self.previous, &self.candidate)
    }

    fn context_for<'a>(
        &'a self,
        expected_before_sha: &'a str,
        expected_after_sha: &'a str,
    ) -> VerificationContext<'a> {
        VerificationContext {
            repository_root: self.directory.path(),
            expected_repository: "ahuazhu/cats",
            expected_rc_ref: "refs/heads/rc/architecture-v2",
            expected_rc_branch: "rc/architecture-v2",
            expected_controller_sha: &self.previous,
            expected_before_sha,
            expected_after_sha,
            trusted_main_head_sha: &self.candidate,
            expected_required_checks: REQUIRED_CHECKS,
        }
    }
}

#[test]
fn reviewed_pr_fast_forward_is_accepted_and_exact_rerun_is_stable() {
    let repository = TestRepository::create();
    let record = repository
        .record("reviewed-pr.json")
        .expect("valid fixture");
    let first = verify_source_chain(&record, &repository.context()).expect("valid source chain");
    let rerun = verify_source_chain(&record, &repository.context()).expect("idempotent rerun");

    assert_eq!(first, rerun);
    assert_eq!(first.integration_kind, IntegrationKind::ReviewedPullRequest);
    assert_eq!(first.previous_rc_sha, repository.previous);
    assert_eq!(first.candidate_sha, repository.candidate);
    assert_ne!(first.controller_sha, first.candidate_sha);
}

#[test]
fn malformed_record_is_rejected_before_git_validation() {
    let repository = TestRepository::create();
    let error = repository
        .record("malformed.json")
        .expect_err("malformed JSON must fail");
    assert!(error.is_eof(), "unexpected parse failure: {error}");
}

#[test]
fn non_fast_forward_edge_is_rejected() {
    assert_rejected("non-ff.json", "not a fast-forward");
}

#[test]
fn candidate_must_match_the_exact_trusted_push_after_sha() {
    assert_rejected("wrong-head.json", "does not match trusted push evidence");
}

#[test]
fn reviewed_pr_requires_an_independent_approval() {
    assert_rejected("unreviewed.json", "at least one approval");
}

#[test]
fn main_pr_cannot_be_substituted_for_an_rc_pr() {
    assert_rejected("main-only.json", "integration.base_ref");
}

#[test]
fn forced_push_event_is_rejected_even_when_the_graph_is_ancestral() {
    assert_rejected("forced-push.json", "forced RC movement");
}

#[test]
fn emergency_sync_requires_and_accepts_the_exact_trusted_main_head() {
    let repository = TestRepository::create();
    let record = repository
        .record("emergency-sync.json")
        .expect("valid fixture");
    let verdict =
        verify_source_chain(&record, &repository.context()).expect("valid emergency main sync");
    assert_eq!(verdict.integration_kind, IntegrationKind::EmergencyMainSync);
    assert_eq!(verdict.candidate_sha, repository.candidate);
}

#[test]
fn accepted_edge_replays_after_the_live_rc_ref_advances() {
    let repository = TestRepository::create();
    let record = repository
        .record("reviewed-pr.json")
        .expect("valid fixture");
    let original =
        verify_source_chain(&record, &repository.context()).expect("accept original RC edge");

    git(
        repository.directory.path(),
        &["checkout", "rc/architecture-v2"],
    );
    fs::write(repository.directory.path().join("state"), "later RC\n")
        .expect("write later RC tree");
    git(repository.directory.path(), &["commit", "-am", "later RC"]);
    let live_rc_head = rev_parse(repository.directory.path(), "refs/heads/rc/architecture-v2");
    assert_ne!(live_rc_head, repository.candidate);

    let replay = verify_source_chain(&record, &repository.context())
        .expect("historical edge must not depend on the mutable live RC ref");
    assert_eq!(replay, original);
}

#[test]
fn missing_required_check_is_rejected_against_trusted_policy() {
    assert_rejected("missing-check.json", "missing=[\"CI\"]");
}

#[test]
fn fake_success_check_cannot_replace_the_trusted_required_check() {
    assert_rejected("fake-check.json", "unexpected=[\"fake\"]");
}

#[test]
fn historical_second_emergency_sync_example_binds_the_exact_known_edge() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/historical-emergency-syncs.example.json"),
    )
    .expect("read historical emergency sync example");
    let example: serde_json::Value = serde_json::from_str(&source).expect("parse example");

    assert_eq!(
        example["schema"],
        "cats.rc-emergency-sync-history.example.v1"
    );
    assert_eq!(example["qualification_evidence"], false);
    assert_eq!(
        example["edges"][1]["before_sha"],
        "4711b49a4d82099db82fbf6351e4054f60cf7913"
    );
    assert_eq!(
        example["edges"][1]["after_sha"],
        "d0658064764ee5d77430662fdc8f4c7fda120189"
    );
}

fn assert_rejected(fixture: &str, expected: &str) {
    let repository = TestRepository::create();
    let record = repository.record(fixture).expect("parse rejection fixture");
    let context = if fixture == "non-ff.json" {
        repository.context_for(&repository.diverged, &repository.candidate)
    } else {
        repository.context()
    };
    let error = verify_source_chain(&record, &context)
        .expect_err("source-chain fixture must be rejected")
        .to_string();
    assert!(
        error.contains(expected),
        "expected {expected:?} in rejection, found {error:?}"
    );
}

fn git(repository: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .current_dir(repository)
        .args(arguments)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn rev_parse(repository: &Path, revision: &str) -> String {
    let output = Command::new("git")
        .current_dir(repository)
        .args(["rev-parse", revision])
        .output()
        .expect("run git rev-parse");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("Git SHA is UTF-8")
        .trim()
        .to_owned()
}
