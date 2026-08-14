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
fn workers_are_read_only_and_only_the_gateway_can_publish_chunkstore_objects() {
    let main = read_workspace_file("deploy/aws/terraform/stacks/platform/main.tf");
    let worker = between(
        &main,
        "data \"aws_iam_policy_document\" \"metal_worker_chunkstore\"",
        "resource \"aws_iam_role_policy\" \"metal_worker_chunkstore\"",
    );
    for contract in [
        "sid    = \"DenyDirectChunkStoreMutation\"",
        "effect = \"Deny\"",
        "\"s3:AbortMultipartUpload\"",
        "\"s3:DeleteObject\"",
        "\"s3:PutObject\"",
        "${aws_s3_bucket.chunkstore.arn}/${var.chunkstore_prefix}/*",
    ] {
        assert!(worker.contains(contract), "missing worker deny: {contract}");
    }
    assert!(!worker.contains("ReadWriteChunkStore"));

    let gateway = between(
        &main,
        "data \"aws_iam_policy_document\" \"object_write_gateway_chunkstore\"",
        "resource \"aws_iam_role_policy\" \"object_write_gateway_chunkstore\"",
    );
    for contract in [
        "\"s3:GetObject\"",
        "\"s3:GetObjectAttributes\"",
        "\"s3:PutObject\"",
        "variable = \"s3:prefix\"",
        "${aws_s3_bucket.chunkstore.arn}/${var.chunkstore_prefix}/*",
    ] {
        assert!(
            gateway.contains(contract),
            "missing gateway least-privilege contract: {contract}"
        );
    }
    for forbidden in [
        "s3:DeleteObject",
        "s3:PutBucket",
        "ec2:",
        "iam:",
        "Resource = [\"*\"]",
    ] {
        assert!(
            !gateway.contains(forbidden),
            "gateway gained forbidden authority: {forbidden}"
        );
    }

    let association = between(
        &main,
        "resource \"aws_eks_pod_identity_association\" \"object_write_gateway\"",
        "# HostFence provider permissions",
    );
    assert!(association.contains("service_account = var.object_write_gateway_service_account"));
    assert!(association.contains("role_arn        = aws_iam_role.object_write_gateway.arn"));
}

#[test]
fn host_fence_mutations_are_exact_targets_and_network_is_secondary_only() {
    let main = read_workspace_file("deploy/aws/terraform/stacks/platform/main.tf");
    let provider = between(
        &main,
        "data \"aws_iam_policy_document\" \"host_fence_provider\"",
        "resource \"aws_iam_role_policy\" \"host_fence_provider\"",
    );
    for contract in [
        "\"ec2:DescribeInstances\"",
        "\"ec2:DescribeNetworkInterfaces\"",
        "actions = [\"ec2:StopInstances\"]",
        "for worker in aws_instance.metal_worker",
        ":instance/${worker.id}",
        "actions = [\"ec2:ModifyNetworkInterfaceAttribute\"]",
        ":network-interface/${worker.primary_network_interface_id}",
        "sid    = \"DenyControlPlaneChunkStoreMutation\"",
    ] {
        assert!(
            provider.contains(contract),
            "missing exact HostFence IAM contract: {contract}"
        );
    }
    for forbidden in [
        "ec2:StartInstances",
        "ec2:TerminateInstances",
        "ec2:CreateSecurityGroup",
        "ec2:AuthorizeSecurityGroup",
        "iam:",
    ] {
        assert!(
            !provider.contains(forbidden),
            "HostFence role gained forbidden mutation: {forbidden}"
        );
    }

    let quarantine = between(
        &main,
        "resource \"aws_security_group\" \"metal_worker_fence\"",
        "resource \"aws_ecr_repository\"",
    );
    assert!(quarantine.contains("Authority = \"secondary-only\""));
    assert!(!quarantine.contains("ingress {"));
    assert!(!quarantine.contains("egress {"));
    assert!(!main.contains("resource \"aws_vpc_security_group_egress_rule\" \"metal_worker_fence"));
    assert!(!main.contains("resource \"aws_vpc_security_group_ingress_rule\" \"metal_worker_fence"));

    let outputs = read_workspace_file("deploy/aws/terraform/stacks/platform/outputs.tf");
    for binding in [
        "provider                       = \"aws\"",
        "partition                      = data.aws_partition.current.partition",
        "account_id                     = var.expected_account_id",
        "region                         = var.aws_region",
        "immutable_host_id              = worker.id",
        "primary_network_interface_id   = worker.primary_network_interface_id",
        "network_quarantine_boundary_id = aws_security_group.metal_worker_fence.id",
        "object_store_bucket            = aws_s3_bucket.chunkstore.id",
        "object_store_prefix            = var.chunkstore_prefix",
    ] {
        assert!(
            outputs.contains(binding),
            "missing binding output: {binding}"
        );
    }
}

#[test]
fn chunkstore_scope_and_service_accounts_are_explicit_validated_inputs() {
    let variables = read_workspace_file("deploy/aws/terraform/stacks/platform/variables.tf");
    let prefix = between(
        &variables,
        "variable \"chunkstore_prefix\"",
        "variable \"chunkstore_versioning_enabled\"",
    );
    for contract in [
        "!startswith(var.chunkstore_prefix, \"/\")",
        "!endswith(var.chunkstore_prefix, \"/\")",
        "!strcontains(var.chunkstore_prefix, \"..\")",
        "!strcontains(var.chunkstore_prefix, \"//\")",
    ] {
        assert!(prefix.contains(contract));
    }
    for input in [
        "variable \"object_write_gateway_namespace\"",
        "variable \"object_write_gateway_service_account\"",
        "variable \"host_fence_provider_namespace\"",
        "variable \"host_fence_provider_service_account\"",
    ] {
        assert!(variables.contains(input), "missing explicit input: {input}");
    }
}
