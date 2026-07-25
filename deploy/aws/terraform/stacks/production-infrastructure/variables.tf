variable "aws_region" {
  description = "AWS region containing the Cats production platform."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "production"
}

variable "eks_cluster_name" {
  description = "Existing EKS cluster used by the Cats production application."
  type        = string
}

variable "usage_archive_bucket_name" {
  description = "Globally unique S3 bucket name for the immutable raw usage archive."
  type        = string
}

variable "usage_archive_object_lock_days" {
  description = "Default governance retention for archived raw usage objects."
  type        = number
  default     = 2555
}

variable "usage_kinesis_shard_count" {
  description = "Provisioned Kinesis shard count. Start at one and scale from measured throughput."
  type        = number
  default     = 1
}

variable "usage_kinesis_retention_hours" {
  description = "Kinesis replay window; S3 remains the long-term source."
  type        = number
  default     = 24
}

variable "usage_consumer_lag_alarm_threshold_ms" {
  description = "Maximum stream iterator age before alerting on stale provisional billing."
  type        = number
  default     = 60000
}

variable "alarm_sns_topic_arns" {
  description = "SNS topics notified by usage-pipeline CloudWatch alarms."
  type        = list(string)
  default     = []
}

variable "worker_artifact_bucket_name" {
  description = "Globally unique S3 bucket used for immutable metal-worker deployment bundles."
  type        = string
}

variable "worker_bundle_path" {
  description = "Absolute path to the reviewed linux/amd64 worker tar.zst bundle."
  type        = string
}

variable "worker_bundle_sha256" {
  description = "SHA-256 digest for worker_bundle_path."
  type        = string
}

variable "metal_worker_instance_id" {
  description = "Existing production bare-metal worker EC2 instance."
  type        = string
}

variable "metal_worker_instance_role_name" {
  description = "Existing IAM role attached to the production bare-metal worker."
  type        = string
}

variable "worker_runtime_secret_data" {
  description = "Worker CATS_AUTH_TOKEN and CATS_POSTGRES_URL delivered through Secrets Manager."
  type        = map(string)
  sensitive   = true
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}
