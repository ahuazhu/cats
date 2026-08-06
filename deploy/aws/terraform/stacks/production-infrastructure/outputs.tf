output "usage_stream_name" {
  value = module.usage_infrastructure.kinesis_stream_name
}

output "usage_archive_bucket_name" {
  value = module.usage_infrastructure.archive_bucket_name
}

output "usage_consumer_lease_table_name" {
  value = module.usage_infrastructure.consumer_lease_table_name
}

output "usage_producer_policy_arn" {
  value = module.usage_infrastructure.producer_policy_arn
}

output "usage_consumer_policy_arn" {
  value = module.usage_infrastructure.consumer_policy_arn
}

output "usage_replay_policy_arn" {
  value = module.usage_infrastructure.replay_policy_arn
}

output "usage_pipeline_role_arn" {
  value = module.usage_infrastructure.pipeline_role_arn
}

output "usage_pod_identity_association_id" {
  value = module.usage_infrastructure.pod_identity_association_id
}

output "route_cache_table_name" {
  description = "Regional shared cache for already-signed Endpoint Route Grants."
  value       = module.route_cache_infrastructure.table_name
}

output "route_cache_gateway_role_arn" {
  description = "Pod Identity role used by cats-gatewayd for the shared Route Grant cache."
  value       = module.route_cache_infrastructure.gateway_role_arn
}

output "route_cache_pod_identity_association_id" {
  description = "Gateway Pod Identity association ID."
  value       = module.route_cache_infrastructure.pod_identity_association_id
}

output "worker_artifact_bucket_name" {
  value = one(module.metal_worker_deployment[*].artifact_bucket_name)
}

output "worker_bundle_key" {
  value = one(module.metal_worker_deployment[*].worker_bundle_key)
}

output "worker_deployment_association_ids" {
  value = one(module.metal_worker_deployment[*].association_ids)
}

output "worker_runtime_secret_arn" {
  value = one(module.metal_worker_deployment[*].runtime_secret_arn)
}

output "credential_refresher_role_arn" {
  description = "Pod Identity role the in-cluster credential refresher assumes. Null until database_master_user_secret_arn is set."
  value       = try(aws_iam_role.credential_refresher[0].arn, null)
}
