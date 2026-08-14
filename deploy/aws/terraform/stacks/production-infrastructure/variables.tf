variable "aws_region" {
  description = "Exact AWS region containing the Cats production platform."
  type        = string
  default     = "us-east-1"
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be an explicit AWS region name."
  }
}

variable "expected_account_id" {
  description = "Exact AWS account allowed to contain the production infrastructure."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be an explicit 12-digit AWS account ID."
  }
}

variable "expected_aws_partition" {
  description = "Exact AWS partition allowed to contain the production infrastructure."
  type        = string
  default     = "aws"
  nullable    = false

  validation {
    condition = contains([
      "aws",
      "aws-cn",
      "aws-iso",
      "aws-iso-b",
      "aws-iso-e",
      "aws-iso-f",
      "aws-us-gov",
    ], var.expected_aws_partition)
    error_message = "expected_aws_partition must name one supported AWS partition."
  }
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

  validation {
    condition = (
      var.chunkstore_prefix != "" &&
      !startswith(var.chunkstore_prefix, "/") &&
      !endswith(var.chunkstore_prefix, "/") &&
      !strcontains(var.chunkstore_prefix, "..") &&
      !strcontains(var.chunkstore_prefix, "//") &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$", var.chunkstore_prefix))
    )
    error_message = "chunkstore_prefix must be one non-empty relative canonical prefix."
  }
}

variable "control_postgres_schema" {
  description = "Exact fresh cats_* PostgreSQL schema shared by controld, noded and every blockd."
  type        = string

  validation {
    condition     = can(regex("^cats_[a-z0-9_]+$", var.control_postgres_schema)) && length(var.control_postgres_schema) <= 63
    error_message = "control_postgres_schema must be one lowercase cats_* PostgreSQL identifier no longer than 63 bytes."
  }
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

variable "platform_alert_sns_topic_arn" {
  description = "Exact alert_sns_topic_arn output from the reviewed platform Terraform state. Every usage-pipeline alarm uses this topic."
  type        = string
  nullable    = false

  validation {
    condition = (
      var.platform_alert_sns_topic_arn == join(":", [
        "arn",
        var.expected_aws_partition,
        "sns",
        var.aws_region,
        var.expected_account_id,
        "cats-${var.environment}-alerts",
      ])
    )
    error_message = "platform_alert_sns_topic_arn must exactly match the expected partition, account, region, and cats-<environment>-alerts platform output."
  }
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
    CATS_POSTGRES_SSLMODE, CATS_POSTGRES_SESSION_SETUP. The exact search_path
    comes only from the separate required control_postgres_schema input.
  EOT
  type        = map(string)
  default     = {}
}

variable "worker_runtime_secret_data" {
  description = "Optional legacy CATS_POSTGRES_URL compatibility map. Signed workers must not receive CATS_AUTH_TOKEN."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "route_v2_node_artifact_secret_arn" {
  description = "Pre-created Secrets Manager ARN for the exact four-file Node Route v2 artifact set. Terraform receives no artifact bytes."
  type        = string
  default     = ""

  validation {
    condition = (
      var.route_v2_node_artifact_secret_arn == "" ||
      (
        startswith(
          var.route_v2_node_artifact_secret_arn,
          "arn:${var.expected_aws_partition}:secretsmanager:${var.aws_region}:${var.expected_account_id}:secret:cats-${var.environment}-route-v2-node-r1-",
        ) &&
        length(var.route_v2_node_artifact_secret_arn) == length("arn:${var.expected_aws_partition}:secretsmanager:${var.aws_region}:${var.expected_account_id}:secret:cats-${var.environment}-route-v2-node-r1-") + 6 &&
        can(regex("[A-Za-z0-9]{6}$", var.route_v2_node_artifact_secret_arn))
      )
    )
    error_message = "route_v2_node_artifact_secret_arn must be empty or the exact cats-<environment>-route-v2-node-r1 secret ARN in the expected partition, account, and region."
  }
}

variable "route_v2_node_artifact_secret_version_id" {
  description = "Exact Secrets Manager version ID for the revision-1 Node Route v2 artifact secret."
  type        = string
  default     = ""

  validation {
    condition = (
      var.route_v2_node_artifact_secret_version_id == "" ||
      can(regex("^[A-Za-z0-9-]{32,64}$", var.route_v2_node_artifact_secret_version_id))
    )
    error_message = "route_v2_node_artifact_secret_version_id must be empty or a 32-64 character Secrets Manager version ID."
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
