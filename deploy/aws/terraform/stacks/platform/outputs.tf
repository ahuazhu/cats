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

output "metal_worker_role_name" {
  description = "Feed to the infrastructure stack's metal_worker_instance_role_name."
  value       = aws_iam_role.metal_worker.name
}

output "metal_worker_instance_profile" {
  value = aws_iam_instance_profile.metal_worker.name
}

output "metal_worker_instance_ids" {
  value = aws_instance.metal_worker[*].id
}

output "metal_worker_private_ips" {
  value = aws_instance.metal_worker[*].private_ip
}

output "instance_connect_endpoint_id" {
  value = one(aws_ec2_instance_connect_endpoint.workers[*].id)
}
