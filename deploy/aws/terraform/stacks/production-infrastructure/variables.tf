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

variable "chunkstore_bucket_name" {
  description = "Platform stack chunkstore_bucket_name output."
  type        = string
}

variable "chunkstore_prefix" {
  description = "Exact object-key prefix used by blockd and cats-controld."
  type        = string
  default     = "cats"
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
# the vCPU quota one requires. Leaving metal_worker_instances empty skips the
# worker module so the usage side can go up first, then fills it in later.
variable "metal_worker_enabled" {
  description = "Manage the bare-metal worker release path. Defaults to whether metal_worker_instances is set."
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

variable "metal_worker_instances" {
  description = "Existing production bare-metal worker EC2 instances, keyed by a stable worker name such as \"metal-1\"."
  type        = map(string)
  default     = {}
}

variable "metal_worker_deploy_instances" {
  description = "Worker names to (re)deploy this apply; null deploys every worker. Roll a release across a serving fleet one drained worker at a time."
  type        = set(string)
  default     = null
  nullable    = true
}

variable "metal_worker_instance_role_name" {
  description = "Existing IAM role shared by every production bare-metal worker."
  type        = string
  default     = ""
}

variable "database_master_user_secret_arn" {
  description = <<-EOT
    Platform stack's database_master_user_secret_arn output. Set it and the
    worker renders its DSN from the RDS managed secret at every start and on a
    timer; leave it null and the worker keeps the static copy in worker.env,
    which is what a rotation silently invalidates.
  EOT
  type        = string
  default     = null
}

variable "worker_managed_environment" {
  description = <<-EOT
    Non-secret worker.env entries Terraform rewrites on every deployment, so
    they reach a host that already has the file. Carries the non-secret half of
    the DSN: CATS_POSTGRES_HOST, CATS_POSTGRES_PORT, CATS_POSTGRES_DATABASE,
    CATS_POSTGRES_SSLMODE, CATS_POSTGRES_SESSION_SETUP.
  EOT
  type        = map(string)
  default     = {}
}

variable "worker_runtime_secret_data" {
  description = "Worker CATS_AUTH_TOKEN delivered through Secrets Manager. A legacy CATS_POSTGRES_URL is still accepted but no longer read."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "route_grant_public_key_pem" {
  description = "Ed25519 public key deployed to every metal worker for Route Grant verification."
  type        = string
  default     = ""

  validation {
    condition = (
      var.route_grant_public_key_pem == "" || (
        startswith(trimspace(var.route_grant_public_key_pem), "-----BEGIN PUBLIC KEY-----") &&
        endswith(trimspace(var.route_grant_public_key_pem), "-----END PUBLIC KEY-----")
      )
    )
    error_message = "route_grant_public_key_pem must be empty or a PEM public key."
  }
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

variable "credential_refresher_namespace" {
  description = "Namespace of the ServiceAccount the credential refresher runs as. Must match the application stack."
  type        = string
  default     = "cats"
}

variable "credential_refresher_service_account" {
  description = "ServiceAccount the credential refresher runs as. Must match the application stack."
  type        = string
  default     = "cats-credential-refresher"
}
