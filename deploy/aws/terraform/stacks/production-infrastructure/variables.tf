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

# The usage pipeline and the worker release path share this state but not a
# schedule. The control plane needs Kinesis, the archive and the checkpoint
# table before it can serve anything; the worker release path needs a
# bare-metal instance that may not exist yet -- new accounts start well below
# the vCPU quota one requires. Leaving metal_worker_instance_id empty skips the
# worker module so the usage side can go up first, then fills it in later.
variable "metal_worker_enabled" {
  description = "Manage the bare-metal worker release path. Defaults to whether metal_worker_instance_id is set."
  type        = bool
  default     = null
}

variable "worker_bundle_path" {
  description = "Absolute path to the reviewed linux/amd64 worker tar.zst bundle."
  type        = string
  default     = ""
}

variable "worker_bundle_sha256" {
  description = "SHA-256 digest for worker_bundle_path."
  type        = string
  default     = ""
}

variable "metal_worker_instance_id" {
  description = "Existing production bare-metal worker EC2 instance."
  type        = string
  default     = ""
}

variable "metal_worker_instance_role_name" {
  description = "Existing IAM role attached to the production bare-metal worker."
  type        = string
  default     = ""
}

variable "worker_runtime_secret_data" {
  description = "Worker CATS_AUTH_TOKEN and CATS_POSTGRES_URL delivered through Secrets Manager."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}

variable "worker_base_environment" {
  description = "Non-secret worker.env entries used to seed a host that has none yet. Passed through to the worker deployment module."
  type        = map(string)
  default     = {}
}
