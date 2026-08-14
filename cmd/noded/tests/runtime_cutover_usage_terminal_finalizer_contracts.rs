use std::io::Write;
use std::process::{Command, Output, Stdio};

use cats_metering::{sha256_prefixed, UsageTerminalSourceExpectation};

const FIRST_RECEIPT: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const SECOND_RECEIPT: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const GOLDEN_BYTES: &str = concat!(
    "[{\"source_id\":\"node/node-a/cat/cat-a\",\"source_epoch\":\"epoch-a\",",
    "\"receipt_sha256\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\"},",
    "{\"source_id\":\"node/node-b/cat/cat-b\",\"source_epoch\":\"epoch-b\",",
    "\"receipt_sha256\":\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"}]"
);
const GOLDEN_SHA256: &str =
    "sha256:1ecc587146a29898f40be96fb88679c68106813997ce5778fc046c86388e2ec1";

fn finalizer() -> &'static str {
    include_str!("../../../deploy/metal/runtime-cutover-usage-terminal-finalize.sh")
}

fn source_set_python() -> String {
    let script = finalizer();
    let (_, after) = script
        .split_once("# SOURCE_SET_CANONICAL_BEGIN\n")
        .expect("source-set canonical begin marker");
    let (body, _) = after
        .split_once("# SOURCE_SET_CANONICAL_END\n")
        .expect("source-set canonical end marker");
    format!(
        concat!(
            "import hashlib,json,sys\n",
            "{body}",
            "try:\n",
            " value=json.load(sys.stdin)\n",
            " sys.stdout.buffer.write(typed_source_set_bytes(value)+b'\\n')\n",
            " print(typed_source_set_sha256(value))\n",
            "except (KeyError,TypeError,ValueError):\n",
            " raise SystemExit(23)\n"
        ),
        body = body
    )
}

fn run_source_set_python(input: &str) -> Output {
    let mut child = Command::new("python3")
        .args(["-c", &source_set_python()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start finalizer source-set canonicalizer");
    child
        .stdin
        .take()
        .expect("canonicalizer stdin")
        .write_all(input.as_bytes())
        .expect("write source-set fixture");
    child.wait_with_output().expect("wait for canonicalizer")
}

#[test]
fn source_set_digest_matches_rust_typed_schema_and_ignores_input_key_order() {
    let sources = vec![
        UsageTerminalSourceExpectation {
            source_id: "node/node-a/cat/cat-a".to_owned(),
            source_epoch: "epoch-a".to_owned(),
            receipt_sha256: FIRST_RECEIPT.to_owned(),
        },
        UsageTerminalSourceExpectation {
            source_id: "node/node-b/cat/cat-b".to_owned(),
            source_epoch: "epoch-b".to_owned(),
            receipt_sha256: SECOND_RECEIPT.to_owned(),
        },
    ];
    let rust_bytes = serde_json::to_vec(&sources).expect("encode typed Rust source set");
    assert_eq!(rust_bytes, GOLDEN_BYTES.as_bytes());
    assert_eq!(sha256_prefixed(&rust_bytes), GOLDEN_SHA256);

    let reordered = format!(
        concat!(
            "[{{\"receipt_sha256\":\"{}\",\"source_epoch\":\"epoch-a\",",
            "\"source_id\":\"node/node-a/cat/cat-a\"}},",
            "{{\"source_epoch\":\"epoch-b\",\"source_id\":\"node/node-b/cat/cat-b\",",
            "\"receipt_sha256\":\"{}\"}}]"
        ),
        FIRST_RECEIPT, SECOND_RECEIPT
    );
    let output = run_source_set_python(&reordered);
    assert!(
        output.status.success(),
        "Python canonicalizer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("canonicalizer UTF-8"),
        format!("{GOLDEN_BYTES}\n{GOLDEN_SHA256}\n")
    );
}

#[test]
fn source_set_canonicalizer_rejects_missing_and_extra_fields() {
    for invalid in [
        "[{\"source_id\":\"node/node-a/cat/cat-a\",\"source_epoch\":\"epoch-a\"}]".to_owned(),
        format!(
            concat!(
                "[{{\"source_id\":\"node/node-a/cat/cat-a\",\"source_epoch\":\"epoch-a\",",
                "\"receipt_sha256\":\"{}\",\"foreign\":true}}]"
            ),
            FIRST_RECEIPT
        ),
    ] {
        let output = run_source_set_python(&invalid);
        assert_eq!(output.status.code(), Some(23));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn finalizer_closes_one_run_wide_target_and_seven_file_evidence_set() {
    let script = finalizer();
    for required in [
        "--kernel-nbd-qualification-dir",
        "--vhost-user-qualification-dir",
        "/v1/admin/usage/target-terminal/begin",
        "/v1/admin/usage/target-terminal/complete",
        "/opt/cats/bin/cats-usage-terminal-receipt-verifier",
        "usage-global-terminal-finalization.manifest.json",
        "usage-target-terminal-verification.receipt.json",
        "usage-terminal-targets.json",
        "case-evidence.jsonl",
        "qualification-catalog.v1.json",
    ] {
        assert!(
            script.contains(required),
            "missing finalizer contract {required}"
        );
    }
    assert!(script.contains("cats.usage-target-terminal-epoch.v1"));
    assert!(script.contains("len(encoded).to_bytes(8, \"big\")"));
    assert!(!script.contains("$BLOCK_PATH"));
    assert!(!script.contains("usage-final-terminal-receipt"));
}
