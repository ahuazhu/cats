variable "name_prefix" {
  description = "Lowercase prefix used for regional resource names."
  type        = string
  default     = "cats"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.name_prefix))
    error_message = "name_prefix must contain 2-31 lowercase letters, digits, or hyphens."
  }
}

variable "environment" {
  description = "Deployment environment, such as production or staging."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.environment))
    error_message = "environment must contain 2-21 lowercase letters, digits, or hyphens."
  }
}

variable "archive_bucket_name" {
  description = "Globally unique name for the dedicated raw usage archive bucket."
  type        = string
}

variable "archive_force_destroy" {
  description = "Emergency/test-only switch. Keep false for production."
  type        = bool
  default     = false
}

variable "archive_object_lock_mode" {
  description = "Default S3 Object Lock retention mode."
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.archive_object_lock_mode)
    error_message = "archive_object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "archive_object_lock_days" {
  description = "Default immutable retention for raw usage evidence. 2555 is approximately seven years."
  type        = number
  default     = 2555

  validation {
    condition     = var.archive_object_lock_days >= 1
    error_message = "archive_object_lock_days must be positive."
  }
}

variable "archive_standard_ia_after_days" {
  description = "Transition batched archive objects to Standard-IA after this many days."
  type        = number
  default     = 30

  validation {
    condition     = var.archive_standard_ia_after_days >= 30
    error_message = "S3 Standard-IA has a 30-day minimum; use at least 30 days."
  }
}

variable "archive_deep_archive_after_days" {
  description = "Transition old raw evidence to Deep Archive after this many days."
  type        = number
  default     = 365

  validation {
    condition     = var.archive_deep_archive_after_days >= 180
    error_message = "Deep Archive transition must be at least 180 days."
  }
}

variable "kinesis_shard_count" {
  description = "Provisioned Kinesis shards. One shard is the cost-conscious initial production default."
  type        = number
  default     = 1

  validation {
    condition     = var.kinesis_shard_count >= 1
    error_message = "kinesis_shard_count must be at least one."
  }
}

variable "kinesis_retention_hours" {
  description = "Kinesis retention. 24 hours is included in the base stream price."
  type        = number
  default     = 24

  validation {
    condition     = var.kinesis_retention_hours >= 24 && var.kinesis_retention_hours <= 8760
    error_message = "kinesis_retention_hours must be between 24 and 8760."
  }
}

variable "consumer_lag_alarm_threshold_ms" {
  description = "Maximum Kinesis iterator age before alerting that provisional billing is stale."
  type        = number
  default     = 60000

  validation {
    condition     = var.consumer_lag_alarm_threshold_ms >= 10000
    error_message = "consumer_lag_alarm_threshold_ms must be at least 10000."
  }
}

variable "alarm_action_arns" {
  description = "SNS topic ARNs notified when provisioned Kinesis capacity throttles."
  type        = list(string)
  default     = []
}

variable "eks_cluster_name" {
  description = "Existing EKS cluster receiving the usage projector Pod Identity association."
  type        = string
}

variable "usage_service_account_namespace" {
  description = "Kubernetes namespace of the usage producer/projector service account."
  type        = string
  default     = "cats"
}

variable "usage_service_account_name" {
  description = "Kubernetes service account used by cats-controld."
  type        = string
  default     = "cats-controld"
}

variable "tags" {
  description = "Additional tags applied to AWS resources."
  type        = map(string)
  default     = {}
}
