output "vpc_id" {
  value = module.network.vpc_id
}

output "public_subnet_ids" {
  value = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  value = module.network.private_subnet_ids
}

output "nat_public_ips" {
  value = module.network.nat_public_ips
}

output "cluster_name" {
  description = "Feed to the infrastructure stack's eks_cluster_name."
  value       = module.cluster.cluster_name
}

output "cluster_endpoint" {
  value = module.cluster.cluster_endpoint
}

output "cluster_security_group_id" {
  value = module.cluster.cluster_security_group_id
}

output "database_endpoint" {
  value = module.database.endpoint
}

output "database_proxy_endpoint" {
  description = "Set this hostname as the RDS_PROXY_ENDPOINT repository variable only after the proxy target is AVAILABLE."
  value       = module.database.proxy_endpoint
}

output "database_name" {
  value = module.database.database_name
}

output "database_master_username" {
  value = module.database.master_username
}

# Read the password out of Secrets Manager to assemble the application stack's
# storage_postgres_url and usage_postgres_url. It is not in this state.
output "database_master_user_secret_arn" {
  value = module.database.master_user_secret_arn
}

output "database_postgresql_log_group_name" {
  description = "Read this before diagnosing a connection failure: the server states the reason here, and nowhere the client can see."
  value       = module.database.postgresql_log_group_name
}

output "database_proxy_connection_setup_alarm_name" {
  value = module.database.proxy_connection_setup_alarm_name
}

output "database_proxy_client_authentication_alarm_name" {
  value = module.database.proxy_client_authentication_alarm_name
}

output "database_proxy_pool_saturation_alarm_name" {
  value = module.database.proxy_pool_saturation_alarm_name
}

output "alert_sns_topic_arn" {
  description = "Copy this exact ARN into the infrastructure stack's platform_alert_sns_topic_arn input."
  value       = aws_sns_topic.alerts.arn
}

output "alert_sns_topic_name" {
  description = "Exact deterministic platform alert topic name."
  value       = local.alert_topic_name
}

output "metal_worker_security_group_id" {
  value = aws_security_group.metal_worker.id
}

output "metal_worker_fence_security_group_id" {
  description = "Explicit deny-all secondary quarantine boundary; never sufficient HostFence authority by itself."
  value       = aws_security_group.metal_worker_fence.id
}

output "route53_zone_id" {
  value = module.dns.zone_id
}

output "route53_name_servers" {
  description = "Set these at the registrar to complete the DNS cutover."
  value       = module.dns.name_servers
}

output "acm_certificate_arn" {
  description = "Feed to the application stack's acm_certificate_arn."
  value       = module.dns.certificate_arn
}

output "ecr_repository_url" {
  value = aws_ecr_repository.control_plane.repository_url
}

output "github_release_role_arn" {
  description = "Set as the AWS_ROLE_ARN repository variable for the release workflow."
  value       = module.github_release.release_role_arn
}

output "chunkstore_bucket_name" {
  value = aws_s3_bucket.chunkstore.id
}

output "chunkstore_prefix" {
  description = "Exact ObjectWrite Gateway-mediated ChunkStore prefix."
  value       = var.chunkstore_prefix
}

output "object_write_gateway_role_arn" {
  description = "Sole Pod Identity role allowed to PutObject in the production ChunkStore prefix."
  value       = aws_iam_role.object_write_gateway.arn
}

output "object_write_gateway_nlb_security_group_id" {
  description = "Internal TLS NLB frontend boundary admitting only the metal worker security group."
  value       = aws_security_group.object_write_gateway_nlb.id
}

output "object_write_gateway_private_zone_id" {
  description = "Private Route53 zone where the application aliases the stable gateway TLS name."
  value       = aws_route53_zone.object_write_internal.zone_id
}

output "object_write_gateway_private_dns_name" {
  description = "Stable release-certificate SAN and CATS_OBJECT_WRITE_GATEWAY_URL host."
  value       = "gateway.${aws_route53_zone.object_write_internal.name}"
}

output "object_write_spool_file_system_id" {
  description = "Encrypted regional EFS file system retaining nonterminal accepted PUT bodies."
  value       = aws_efs_file_system.object_write_spool.id
}

output "object_write_spool_access_point_id" {
  description = "Root-confined EFS access point used by the static ObjectWrite Gateway PV."
  value       = aws_efs_access_point.object_write_spool.id
}

output "object_write_spool_security_group_id" {
  description = "NFS boundary admitting only the exact EKS cluster security group."
  value       = aws_security_group.object_write_spool.id
}

output "host_fence_provider_role_arn" {
  description = "Pod Identity role limited to exact-worker EC2 stop and primary-ENI quarantine."
  value       = aws_iam_role.host_fence_provider.arn
}

output "host_fence_aws_bindings" {
  description = "Provisioned provider scope and immutable AWS targets that NodeIdentity/HostFence configuration must match exactly."
  value = {
    for name, worker in aws_instance.metal_worker : name => {
      provider                       = "aws"
      partition                      = data.aws_partition.current.partition
      account_id                     = var.expected_account_id
      region                         = var.aws_region
      immutable_host_id              = worker.id
      primary_network_interface_id   = worker.primary_network_interface_id
      network_quarantine_boundary_id = aws_security_group.metal_worker_fence.id
      vpc_id                         = module.network.vpc_id
      object_store_bucket            = aws_s3_bucket.chunkstore.id
      object_store_prefix            = var.chunkstore_prefix
      object_store_scope_id          = "${aws_s3_bucket.chunkstore.arn}/${var.chunkstore_prefix}"
    }
  }
}

output "metal_worker_role_name" {
  description = "Feed to the infrastructure stack's metal_worker_instance_role_name."
  value       = aws_iam_role.metal_worker.name
}

output "metal_worker_instance_profile" {
  value = aws_iam_instance_profile.metal_worker.name
}

output "metal_worker_instance_ids" {
  description = "Copy this exact stable-name map into production-infrastructure metal_worker_instances."
  value = {
    for name, worker in aws_instance.metal_worker : name => worker.id
  }
}

output "metal_worker_private_ips" {
  value = {
    for name, worker in aws_instance.metal_worker : name => worker.private_ip
  }
}

output "instance_connect_endpoint_id" {
  value = one(aws_ec2_instance_connect_endpoint.workers[*].id)
}
