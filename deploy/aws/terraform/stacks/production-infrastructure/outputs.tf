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
