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

# Fresh usage transport for the clean-slate cutover. Null until
# fresh_usage_enabled is set. The first three feed the reset executor's
# --fresh-usage-kinesis-stream, --fresh-usage-checkpoint-table and
# --fresh-usage-archive-bucket inputs (its new_usage_* config fields).
output "fresh_usage_kinesis_stream" {
  description = "Fresh usage checkpoint Kinesis stream name; null until fresh_usage_enabled."
  value       = one(module.usage_fresh[*].kinesis_stream_name)
}

output "fresh_usage_checkpoint_table" {
  description = "Fresh DynamoDB projector checkpoint table name; null until fresh_usage_enabled."
  value       = one(module.usage_fresh[*].consumer_lease_table_name)
}

output "fresh_usage_archive_bucket" {
  description = "Fresh immutable raw usage archive bucket; null until fresh_usage_enabled."
  value       = one(module.usage_fresh[*].archive_bucket_name)
}

output "fresh_usage_producer_policy_arn" {
  value = one(module.usage_fresh[*].producer_policy_arn)
}

output "fresh_usage_consumer_policy_arn" {
  value = one(module.usage_fresh[*].consumer_policy_arn)
}

output "fresh_usage_replay_policy_arn" {
  value = one(module.usage_fresh[*].replay_policy_arn)
}

output "fresh_usage_pipeline_role_arn" {
  value = one(module.usage_fresh[*].pipeline_role_arn)
}

output "fresh_usage_pod_identity_association_id" {
  value = one(module.usage_fresh[*].pod_identity_association_id)
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
