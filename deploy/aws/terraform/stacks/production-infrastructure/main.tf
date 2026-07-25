module "usage_infrastructure" {
  source = "../../modules/usage-infrastructure"

  name_prefix                     = "cats"
  environment                     = var.environment
  eks_cluster_name                = var.eks_cluster_name
  archive_bucket_name             = var.usage_archive_bucket_name
  archive_object_lock_days        = var.usage_archive_object_lock_days
  kinesis_shard_count             = var.usage_kinesis_shard_count
  kinesis_retention_hours         = var.usage_kinesis_retention_hours
  consumer_lag_alarm_threshold_ms = var.usage_consumer_lag_alarm_threshold_ms
  alarm_action_arns               = var.alarm_sns_topic_arns
  tags                            = var.tags
}

module "metal_worker_deployment" {
  source = "../../modules/metal-worker-deployment"

  name_prefix                = "cats"
  environment                = var.environment
  artifact_bucket_name       = var.worker_artifact_bucket_name
  worker_bundle_path         = var.worker_bundle_path
  worker_bundle_sha256       = var.worker_bundle_sha256
  instance_id                = var.metal_worker_instance_id
  instance_role_name         = var.metal_worker_instance_role_name
  worker_runtime_secret_data = var.worker_runtime_secret_data
  tags                       = var.tags
}
