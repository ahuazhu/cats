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

locals {
  metal_worker_enabled = (
    var.metal_worker_enabled != null
    ? var.metal_worker_enabled
    : var.metal_worker_instance_id != ""
  )
}

# Guard the half-configured case explicitly. Without it, enabling the worker
# without a bundle fails deep inside the module on an empty S3 key.
resource "terraform_data" "metal_worker_inputs" {
  count = local.metal_worker_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition = alltrue([
        var.metal_worker_instance_id != "",
        var.metal_worker_instance_role_name != "",
        var.worker_bundle_path != "",
        var.worker_bundle_sha256 != "",
        length(var.worker_runtime_secret_data) > 0,
      ])
      error_message = "The metal worker release path needs instance id, instance role, bundle path, bundle sha256 and runtime secret data. Leave metal_worker_instance_id empty to skip it until the hardware exists."
    }
  }
}

module "metal_worker_deployment" {
  source = "../../modules/metal-worker-deployment"

  count = local.metal_worker_enabled ? 1 : 0

  name_prefix                = "cats"
  environment                = var.environment
  artifact_bucket_name       = var.worker_artifact_bucket_name
  worker_bundle_path         = var.worker_bundle_path
  worker_bundle_sha256       = var.worker_bundle_sha256
  instance_id                = var.metal_worker_instance_id
  instance_role_name         = var.metal_worker_instance_role_name
  worker_runtime_secret_data = var.worker_runtime_secret_data
  worker_base_environment    = var.worker_base_environment
  tags                       = var.tags
}
