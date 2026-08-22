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
        "\"ec2:DescribeSecurityGroups\"",
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
        "vpc_id                         = module.network.vpc_id",
        "object_store_bucket            = aws_s3_bucket.chunkstore.id",
        "object_store_prefix            = var.chunkstore_prefix",
        "object_store_scope_id          = \"${aws_s3_bucket.chunkstore.arn}/${var.chunkstore_prefix}\"",
    ] {
        assert!(
            outputs.contains(binding),
            "missing binding output: {binding}"
        );
    }
}

#[test]
fn chunkstore_scope_and_provider_service_accounts_are_exact() {
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
    assert!(!variables.contains("variable \"object_write_gateway_namespace\""));
    assert!(!variables.contains("variable \"object_write_gateway_service_account\""));
    for input in [
        "variable \"host_fence_provider_namespace\"",
        "variable \"host_fence_provider_service_account\"",
    ] {
        assert!(variables.contains(input), "missing explicit input: {input}");
    }
    let host_fence_service_account = between(
        &variables,
        "variable \"host_fence_provider_service_account\"",
        "variable \"metal_workers\"",
    );
    assert!(host_fence_service_account.contains("default     = \"cats-host-fence-provider\""));
    assert!(!host_fence_service_account.contains("cats-controld"));
}

#[test]
fn provider_database_roles_use_distinct_precreated_secrets() {
    let kubernetes = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    assert!(kubernetes.contains("check \"provider_database_credentials_are_separate\""));
    assert!(kubernetes.contains(
        "local.object_write_gateway_postgres_secret_name != local.host_fence_provider_postgres_secret_name"
    ));
    assert!(kubernetes.contains(
        "object_write_gateway_postgres_secret_name = \"cats-object-write-gateway-postgres\""
    ));
    assert!(kubernetes.contains(
        "host_fence_provider_postgres_secret_name  = \"cats-host-fence-provider-postgres\""
    ));
    assert!(
        !kubernetes.contains("resource \"kubernetes_secret_v1\" \"object_write_gateway_database\"")
    );
    let gateway_database = between(
        &kubernetes,
        "volume {\n          name = \"object-write-database\"",
        "volume {\n          name = \"rds-ca\"",
    );
    for contract in [
        "secret_name  = local.object_write_gateway_postgres_secret_name",
        "key  = \"url\"",
        "path = \"url\"",
        "optional     = false",
    ] {
        assert!(
            gateway_database.contains(contract),
            "missing gateway PG mount contract: {contract}"
        );
    }
    assert!(!gateway_database.contains("storage_postgres_url"));
    assert!(kubernetes.contains("/run/cats/object-write-gateway/postgres/url"));
}

#[test]
fn accepted_put_spools_are_encrypted_cross_replica_and_retained() {
    let platform = read_workspace_file("deploy/aws/terraform/stacks/platform/main.tf");
    let file_system = between(
        &platform,
        "resource \"aws_efs_file_system\" \"object_write_spool\"",
        "resource \"aws_efs_backup_policy\" \"object_write_spool\"",
    );
    for contract in [
        "encrypted        = true",
        "performance_mode = \"generalPurpose\"",
        "throughput_mode  = \"elastic\"",
        "prevent_destroy = true",
        "Authority = \"accepted-put-recovery\"",
    ] {
        assert!(
            file_system.contains(contract),
            "missing durable spool contract: {contract}"
        );
    }

    let access_point = between(
        &platform,
        "resource \"aws_efs_access_point\" \"object_write_spool\"",
        "# Static provisioning needs discovery only.",
    );
    for contract in [
        "uid = 10001",
        "gid = 10001",
        "path = \"/object-write-spools\"",
        "permissions = \"0700\"",
    ] {
        assert!(access_point.contains(contract));
    }
    assert!(platform.contains("for_each = toset(module.network.private_subnet_ids)"));
    assert!(platform.contains("resource \"aws_efs_backup_policy\" \"object_write_spool\""));

    let mount_targets = between(
        &platform,
        "resource \"aws_efs_mount_target\" \"object_write_spool\"",
        "resource \"aws_efs_access_point\" \"object_write_spool\"",
    );
    assert!(mount_targets.contains("depends_on = [aws_efs_file_system_policy.object_write_spool]"));

    let file_system_policy = between(
        &platform,
        "data \"aws_iam_policy_document\" \"object_write_spool_client\"",
        "resource \"aws_efs_file_system_policy\" \"object_write_spool\"",
    );
    for contract in [
        "DenyUnencryptedClientAccess",
        "DenyClientAccessOutsideExactAccessPoint",
        "DenyClientAccessOutsideExactNodeRole",
        "DenyClientRootAccess",
        "AllowExactNodeRoleThroughAccessPoint",
        "elasticfilesystem:AccessPointArn",
        "elasticfilesystem:AccessedViaMountTarget",
        "aws:SecureTransport",
        "module.cluster.node_role_arn",
        "aws_efs_access_point.object_write_spool.arn",
        "\"elasticfilesystem:ClientMount\"",
        "\"elasticfilesystem:ClientWrite\"",
    ] {
        assert!(
            file_system_policy.contains(contract),
            "missing EFS client authority boundary: {contract}"
        );
    }
    assert!(platform.contains("resource \"aws_efs_file_system_policy\" \"object_write_spool\""));

    let node_client = between(
        &platform,
        "data \"aws_iam_policy_document\" \"object_write_spool_node_client\"",
        "resource \"aws_iam_role_policy\" \"object_write_spool_node_client\"",
    );
    for contract in [
        "MountAndWriteExactObjectWriteSpool",
        "elasticfilesystem:AccessPointArn",
        "elasticfilesystem:AccessedViaMountTarget",
        "aws_efs_file_system.object_write_spool.arn",
        "aws_efs_access_point.object_write_spool.arn",
    ] {
        assert!(
            node_client.contains(contract),
            "missing exact node-side EFS client authority: {contract}"
        );
    }
    assert!(!node_client.contains("elasticfilesystem:ClientRootAccess"));
    assert!(platform.contains("role   = module.cluster.node_role_name"));

    let nfs = between(
        &platform,
        "resource \"aws_vpc_security_group_ingress_rule\" \"object_write_spool_nfs\"",
        "resource \"aws_efs_mount_target\" \"object_write_spool\"",
    );
    assert!(nfs.contains("referenced_security_group_id = module.cluster.cluster_security_group_id"));
    assert!(nfs.contains("from_port                    = 2049"));
    assert!(!nfs.contains("cidr_ipv4"));

    let csi_policy = between(
        &platform,
        "data \"aws_iam_policy_document\" \"efs_csi_static\"",
        "resource \"aws_iam_role_policy\" \"efs_csi_static\"",
    );
    for forbidden in [
        "elasticfilesystem:CreateAccessPoint",
        "elasticfilesystem:DeleteAccessPoint",
        "elasticfilesystem:ClientWrite",
    ] {
        assert!(!csi_policy.contains(forbidden));
    }

    let cluster = read_workspace_file("deploy/aws/terraform/modules/platform-cluster/main.tf");
    assert!(cluster.contains("addon_name    = \"aws-efs-csi-driver\""));

    let kubernetes = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    let volume = between(
        &kubernetes,
        "resource \"kubernetes_persistent_volume_v1\" \"object_write_spool\"",
        "resource \"kubernetes_persistent_volume_claim_v1\" \"object_write_spool\"",
    );
    for contract in [
        "access_modes                     = [\"ReadWriteMany\"]",
        "persistent_volume_reclaim_policy = \"Retain\"",
        "mount_options                    = [\"tls\", \"iam\"]",
        "driver        = \"efs.csi.aws.com\"",
        "${var.object_write_spool_file_system_id}::${var.object_write_spool_access_point_id}",
        "encryptInTransit = \"true\"",
    ] {
        assert!(
            volume.contains(contract),
            "missing static EFS PV: {contract}"
        );
    }
    let deployment = between(
        &kubernetes,
        "resource \"kubernetes_deployment_v1\" \"object_write_gateway\"",
        "resource \"kubernetes_pod_disruption_budget_v1\" \"object_write_gateway\"",
    );
    assert!(deployment.contains("mount_path = \"/var/lib/cats/object-write-spool\""));
    assert!(deployment.contains("cats-object-write-gatewayd"));
    assert!(deployment.contains("max_unavailable = \"0\""));
}

#[test]
fn object_write_gateway_is_private_tls_passthrough_from_exact_workers() {
    let platform = read_workspace_file("deploy/aws/terraform/stacks/platform/main.tf");
    let ingress = between(
        &platform,
        "resource \"aws_vpc_security_group_ingress_rule\" \"object_write_gateway_nlb_from_workers\"",
        "resource \"aws_vpc_security_group_egress_rule\" \"object_write_gateway_nlb_to_cluster\"",
    );
    for contract in [
        "referenced_security_group_id = aws_security_group.metal_worker.id",
        "from_port                    = 443",
        "to_port                      = 443",
    ] {
        assert!(ingress.contains(contract));
    }
    assert!(!ingress.contains("cidr_ipv4"));
    assert!(!ingress.contains("0.0.0.0/0"));

    let kubernetes = read_workspace_file("deploy/aws/terraform/modules/cats-kubernetes/main.tf");
    let service = between(
        &kubernetes,
        "resource \"kubernetes_service_v1\" \"object_write_gateway\"",
        "resource \"kubernetes_deployment_v1\" \"gateway\"",
    );
    for contract in [
        "aws-load-balancer-scheme\"                              = \"internal\"",
        "aws-load-balancer-nlb-target-type\"                     = \"ip\"",
        "aws-load-balancer-security-groups\"                     = var.object_write_gateway_nlb_security_group_id",
        "aws-load-balancer-subnets\"                             = join(\",\", var.object_write_gateway_private_subnet_ids)",
        "load_balancer_class = \"eks.amazonaws.com/nlb\"",
        "port        = 443",
        "target_port = \"https\"",
    ] {
        assert!(service.contains(contract), "missing private NLB: {contract}");
    }
    for forbidden in [
        "internet-facing",
        "aws-load-balancer-ssl-cert",
        "0.0.0.0/0",
        "type = \"ClusterIP\"",
    ] {
        assert!(
            !service.contains(forbidden),
            "forbidden NLB shape: {forbidden}"
        );
    }

    let deployment = between(
        &kubernetes,
        "resource \"kubernetes_deployment_v1\" \"object_write_gateway\"",
        "resource \"kubernetes_pod_disruption_budget_v1\" \"object_write_gateway\"",
    );
    for contract in [
        "object-write-server-certificate.pem object-write-server-private-key.pem",
        "test \"$actual_count\" = 2",
        "\"0.0.0.0:7443\"",
        "--control-store-url-file",
        "--control-store-ca-file",
        "--server-certificate-file",
        "--server-private-key-file",
        "--durable-spool-root",
        "\"/var/lib/cats/object-write-spool\"",
        "\"--provider\"",
        "\"--partition\"",
        "\"--account-id\"",
        "\"--region\"",
        "\"--bucket\"",
        "\"--prefix\"",
        "\"--object-store-scope-id\"",
        "arn:${var.object_write_provider_partition}:s3:::${var.chunkstore_bucket_name}/${var.chunkstore_prefix}",
        "container_port = 7443",
        "scheme = \"HTTPS\"",
    ] {
        assert!(deployment.contains(contract), "missing Pod TLS: {contract}");
    }
    for stale in [
        "0.0.0.0:7444",
        "--object-store-adapter",
        "--object-store-option",
        "--object-provider-partition",
        "--object-provider-account-id",
    ] {
        assert!(
            !deployment.contains(stale),
            "stale pre-freeze gateway argument remains: {stale}"
        );
    }

    let nlb_egress = between(
        &platform,
        "resource \"aws_vpc_security_group_egress_rule\" \"object_write_gateway_nlb_to_cluster\"",
        "# A stable private name is required",
    );
    assert!(nlb_egress.contains("from_port                    = 7443"));
    assert!(nlb_egress.contains("to_port                      = 7443"));

    let application =
        read_workspace_file("deploy/aws/terraform/stacks/production-application/main.tf");
    assert!(application.contains("resource \"aws_route53_record\" \"object_write_gateway\""));
    assert!(application.contains("type    = \"CNAME\""));
    let outputs =
        read_workspace_file("deploy/aws/terraform/stacks/production-application/outputs.tf");
    assert!(outputs.contains("value       = \"node-server-ca-bundle.pem\""));
    assert!(
        outputs.contains("value       = \"https://${var.object_write_gateway_private_dns_name}\"")
    );
}
