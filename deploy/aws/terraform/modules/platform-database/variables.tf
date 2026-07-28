variable "name_prefix" {
  type        = string
  description = "Resource name prefix."
  default     = "cats"
}

variable "environment" {
  type        = string
  description = "Deployment environment name."
}

variable "vpc_id" {
  type        = string
  description = "VPC hosting the instance."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets for the DB subnet group."
}

variable "allowed_security_group_ids" {
  type        = map(string)
  description = <<-EOT
    Security groups allowed to reach port 5432, keyed by a stable label such as
    "cluster" or "metal_worker". A map rather than a list because the ids are
    only known after apply, and for_each needs keys that are known during plan.
  EOT
  default     = {}
}

variable "engine_version" {
  type        = string
  description = "PostgreSQL engine version."
  default     = "16.13"
}

variable "instance_class" {
  type        = string
  description = "Instance class."
  default     = "db.t4g.micro"
}

variable "allocated_storage" {
  type        = number
  description = "Allocated storage in GiB."
  default     = 20
}

variable "max_allocated_storage" {
  type        = number
  description = "Storage autoscaling ceiling in GiB. Set equal to allocated_storage to disable."
  default     = 100
}

variable "initial_database_name" {
  type        = string
  description = "Database created with the instance."
  default     = "cats"
}

variable "master_username" {
  type        = string
  description = "Master username. The password is managed in Secrets Manager."
  default     = "catsadmin"
}

variable "multi_az" {
  type        = bool
  description = "Multi-AZ standby."
  default     = false
}

variable "backup_retention_days" {
  type        = number
  description = "Automated backup retention in days."
  default     = 7

  validation {
    condition     = var.backup_retention_days >= 1
    error_message = "Keep at least one day of backups; this instance holds the authoritative ChunkStore roots and fencing epochs."
  }
}

variable "deletion_protection" {
  type        = bool
  description = "Block deletion through the API."
  default     = true
}

variable "skip_final_snapshot" {
  type        = bool
  description = "Skip the final snapshot on destroy."
  default     = false
}

variable "apply_immediately" {
  type        = bool
  description = "Apply modifications immediately instead of in the maintenance window."
  default     = false
}

variable "performance_insights_enabled" {
  type        = bool
  description = "Performance Insights. Not supported on every burstable class."
  default     = false
}

variable "tags" {
  type        = map(string)
  description = "Additional tags."
  default     = {}
}
