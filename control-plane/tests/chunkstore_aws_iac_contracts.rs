use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn read_workspace_file(path: &str) -> String {
    let path = workspace_root().join(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .and_then(|(_, tail)| tail.split_once(end))
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("missing contract boundary {start:?} .. {end:?}"))
}

#[test]
fn workers_can_publish_only_inside_the_exact_chunkstore_prefix() {
    let main = read_workspace_file("deploy/aws/terraform/stacks/platform/main.tf");
    let worker = between(
        &main,
        "data \"aws_iam_policy_document\" \"metal_worker_chunkstore\"",
        "resource \"aws_iam_role_policy\" \"metal_worker_chunkstore\"",
    );
    for contract in [
        "sid    = \"ReadWriteChunkStore\"",
        "effect = \"Allow\"",
        "\"s3:DeleteObject\"",
        "\"s3:GetObject\"",
        "\"s3:PutObject\"",
        "${aws_s3_bucket.chunkstore.arn}/${var.chunkstore_prefix}/*",
    ] {
        assert!(
            worker.contains(contract),
            "missing worker scope: {contract}"
        );
    }
    for forbidden in ["s3:PutBucket", "ec2:", "iam:", "Resource = [\"*\"]"] {
        assert!(
            !worker.contains(forbidden),
            "worker gained forbidden authority: {forbidden}"
        );
    }
}
