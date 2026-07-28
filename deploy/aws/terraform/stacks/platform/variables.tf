variable "aws_region" {
  type        = string
  description = "Region for the whole platform."
  default     = "us-east-1"
}

variable "name_prefix" {
  type        = string
  description = "Resource name prefix."
  default     = "cats"
}

variable "environment" {
  type        = string
  description = "Deployment environment name."
  default     = "production"
}

# Network -------------------------------------------------------------------

variable "vpc_cidr" {
  type        = string
  description = <<-EOT
    VPC CIDR. Must not overlap the per-Cat guest network
    (CATS_GUEST_NETWORK_CIDR, 10.240.0.0/16 by default) — a worker NATs guest
    traffic onto its host interface and an overlap would blackhole it.
  EOT
  default     = "10.20.0.0/16"
}

variable "availability_zone_count" {
  type        = number
  description = "Availability zones to span."
  default     = 2
}

variable "one_nat_gateway_per_az" {
  type        = bool
  description = "One NAT gateway per zone instead of one shared."
  default     = false
}

# Cluster -------------------------------------------------------------------

variable "cluster_name" {
  type        = string
  description = "EKS cluster name."
  default     = "cats-production"
}

variable "kubernetes_version" {
  type        = string
  description = "EKS control plane version."
  default     = "1.34"
}

variable "cluster_public_access_cidrs" {
  type        = list(string)
  description = "CIDRs allowed to reach the public Kubernetes API endpoint."
  default     = ["0.0.0.0/0"]
}

variable "cluster_admin_principal_arns" {
  type        = list(string)
  description = "Extra IAM principals granted cluster admin. The applying principal already has it."
  default     = []
}

# Database ------------------------------------------------------------------

variable "database_engine_version" {
  type        = string
  description = "PostgreSQL engine version."
  default     = "16.13"
}

variable "database_instance_class" {
  type        = string
  description = "RDS instance class."
  default     = "db.t4g.micro"
}

variable "database_allocated_storage" {
  type        = number
  description = "Allocated storage in GiB."
  default     = 20
}

variable "database_multi_az" {
  type        = bool
  description = "Multi-AZ standby."
  default     = false
}

variable "database_backup_retention_days" {
  type        = number
  description = "Automated backup retention in days."
  default     = 7
}

variable "database_deletion_protection" {
  type        = bool
  description = "Block deletion through the API."
  default     = true
}

variable "database_skip_final_snapshot" {
  type        = bool
  description = "Skip the final snapshot on destroy."
  default     = false
}

# DNS -----------------------------------------------------------------------

variable "domain_name" {
  type        = string
  description = "Apex domain."
  default     = "cats.run"
}

variable "wait_for_certificate_validation" {
  type        = bool
  description = <<-EOT
    Block the apply until ACM issues. Keep false for the first apply: the
    registrar still points at the old account's name servers, so validation
    cannot resolve yet. Flip it once the NS change has propagated.
  EOT
  default     = false
}

# Release identity ----------------------------------------------------------

variable "github_repository" {
  type        = string
  description = "owner/name of the repository allowed to push releases."
  default     = "ahuazhu/cats"
}

variable "github_default_branch" {
  type        = string
  description = "Branch allowed to release."
  default     = "main"
}

variable "create_github_oidc_provider" {
  type        = bool
  description = "Create the GitHub OIDC provider. An account may only have one per URL."
  default     = true
}

variable "ecr_repository_name" {
  type        = string
  description = "ECR repository for the control-plane image."
  default     = "cats/control-plane"
}

variable "ecr_image_tag_mutability" {
  type        = string
  description = <<-EOT
    MUTABLE or IMMUTABLE. Deployments pin digests, so this does not affect
    correctness; MUTABLE keeps a re-run of the same commit from failing on a
    duplicate tag.
  EOT
  default     = "MUTABLE"

  validation {
    condition     = contains(["MUTABLE", "IMMUTABLE"], var.ecr_image_tag_mutability)
    error_message = "ecr_image_tag_mutability must be MUTABLE or IMMUTABLE."
  }
}

variable "ecr_keep_last_images" {
  type        = number
  description = "Tagged images to retain."
  default     = 20
}

variable "tags" {
  type        = map(string)
  description = "Additional tags applied to every resource."
  default     = {}
}

variable "chunkstore_bucket_name" {
  description = "Globally unique S3 bucket holding immutable ChunkStore objects."
  type        = string
}

variable "chunkstore_versioning_enabled" {
  description = "Versioning on the ChunkStore bucket. Objects are immutable by construction; this only guards against an erroneous delete."
  type        = bool
  default     = true
}
