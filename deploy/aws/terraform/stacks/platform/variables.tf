variable "aws_region" {
  type        = string
  description = "Exact AWS region for the whole platform."
  default     = "us-east-1"
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be an explicit AWS region name."
  }
}

variable "expected_account_id" {
  type        = string
  description = "Exact AWS account allowed to contain the production platform."
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be an explicit 12-digit AWS account ID."
  }
}

variable "expected_aws_partition" {
  type        = string
  description = "Exact AWS partition allowed to contain the production platform."
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
  default     = true
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

variable "efs_csi_addon_version" {
  type        = string
  description = "Pinned aws-efs-csi-driver EKS add-on version; null selects the cluster default."
  default     = null
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
  default     = true
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

variable "database_log_retention_days" {
  type        = number
  description = "Retention for the exported PostgreSQL error log."
  default     = 30
}

# Alerting -------------------------------------------------------------------

variable "alert_email_recipients" {
  type        = map(string)
  description = "Email recipients keyed by opaque, stable operator IDs. Values are sensitive and each recipient must confirm the AWS subscription mail."
  sensitive   = true
  nullable    = false

  validation {
    condition = (
      alltrue([
        for recipient_id in keys(var.alert_email_recipients) :
        can(regex("^[a-z][a-z0-9_-]{0,63}$", recipient_id))
      ]) &&
      alltrue([
        for address in values(var.alert_email_recipients) :
        address == trimspace(address) && can(regex("^[^@[:space:]]+@[^@[:space:]]+$", address))
      ])
    )
    error_message = "alert_email_recipients must use opaque lowercase IDs and non-empty email values without surrounding whitespace. Terraform cannot prove confirmation; run the alarm-recipient preflight after confirmation."
  }

  validation {
    condition = (
      var.environment != "production" || length(var.alert_email_recipients) > 0
    )
    error_message = "alert_email_recipients must contain at least one recipient in production; an empty map is allowed only outside production."
  }

  validation {
    condition = (
      length(distinct(values(var.alert_email_recipients))) ==
      length(var.alert_email_recipients)
    )
    error_message = "alert_email_recipients must not contain duplicate email values."
  }
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

variable "github_subject_repository" {
  type        = string
  description = "Immutable repository identity used by the GitHub OIDC subject template."
  default     = "ahuazhu@1306468/cats@1308574751"
}

variable "github_default_branch" {
  type        = string
  description = "Branch allowed to release."
  default     = "main"
}

variable "github_actions_application_state_bucket_arn" {
  type        = string
  description = "ARN of the remote-state bucket containing the production application state."

  validation {
    condition     = can(regex("^arn:[^:]+:s3:::[^/]+$", var.github_actions_application_state_bucket_arn))
    error_message = "github_actions_application_state_bucket_arn must be an S3 bucket ARN without a key suffix."
  }
}

variable "github_actions_application_state_key" {
  type        = string
  description = "Exact remote-state object key the main-branch deployment may update."
  default     = "cats/production/application.tfstate"

  validation {
    condition = (
      length(trimspace(var.github_actions_application_state_key)) > 0 &&
      !startswith(var.github_actions_application_state_key, "/") &&
      !endswith(var.github_actions_application_state_key, "/")
    )
    error_message = "github_actions_application_state_key must be a non-empty object key without leading or trailing slash."
  }
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

variable "chunkstore_prefix" {
  description = "Exact production object-key prefix mediated by the ObjectWrite Gateway."
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

variable "chunkstore_versioning_enabled" {
  description = "Versioning on the ChunkStore bucket. Objects are immutable by construction; this only guards against an erroneous delete."
  type        = bool
  default     = true
}

variable "metal_worker_ssh_from_instance_connect" {
  description = "Allow sshd on the worker from an EC2 Instance Connect Endpoint in the same security group. The endpoint itself is created outside this stack."
  type        = bool
  default     = true
}

variable "host_fence_provider_namespace" {
  description = "Kubernetes namespace containing the AWS HostFence provider."
  type        = string
  default     = "cats"

  validation {
    condition     = can(regex("^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$", var.host_fence_provider_namespace))
    error_message = "host_fence_provider_namespace must be a DNS-label Kubernetes namespace."
  }
}

variable "host_fence_provider_service_account" {
  description = "Dedicated Kubernetes ServiceAccount allowed to stop only Cats workers and quarantine only their primary ENIs."
  type        = string
  default     = "cats-host-fence-provider"

  validation {
    condition     = can(regex("^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$", var.host_fence_provider_service_account))
    error_message = "host_fence_provider_service_account must be a DNS-label Kubernetes ServiceAccount name."
  }
}

variable "metal_workers" {
  description = <<-EOT
    Bare-metal workers keyed by their stable Node name. subnet_index pins the
    existing Host to one private subnet without making list position an
    identity. root_volume_encrypted records the live root contract: only the
    legacy metal-2 may temporarily be false, and changing it to true is the
    explicit forward-only replacement requested for the maintenance window.
  EOT
  type = map(object({
    subnet_index          = number
    root_volume_encrypted = bool
  }))
  default = {
    metal-1 = {
      subnet_index          = 0
      root_volume_encrypted = true
    }
  }

  validation {
    condition     = length(var.metal_workers) > 0
    error_message = "metal_workers must contain at least one worker."
  }

  validation {
    condition = alltrue([
      for name, worker in var.metal_workers :
      can(regex("^metal-[1-9][0-9]*$", name)) &&
      worker.subnet_index >= 0 &&
      floor(worker.subnet_index) == worker.subnet_index
    ])
    error_message = "metal_workers keys must be stable metal-<positive integer> names with non-negative integer subnet_index values."
  }

  validation {
    condition = alltrue([
      for name, worker in var.metal_workers :
      worker.root_volume_encrypted || name == "metal-2"
    ])
    error_message = "Only the known legacy metal-2 root may temporarily remain unencrypted."
  }
}

variable "metal_worker_instance_type" {
  description = "Worker instance type. Must be .metal for /dev/kvm, and should carry instance storage: the ChunkStore cache on EBS measures 14-43x lower on 4 KiB random write."
  type        = string
  default     = "c5d.metal"

  validation {
    condition     = endswith(var.metal_worker_instance_type, ".metal")
    error_message = "Cloud Hypervisor needs /dev/kvm, which only bare-metal instance types expose."
  }
}

variable "metal_worker_ami" {
  description = "Pinned Ubuntu 24.04 LTS x86_64 AMI. Pinned deliberately: tracking the latest publication would recycle running workers."
  type        = string
}

variable "metal_worker_root_volume_gib" {
  description = "Root volume size. The guest image build and package cache need room; the ChunkStore cache lives on instance storage."
  type        = number
  default     = 200
}
