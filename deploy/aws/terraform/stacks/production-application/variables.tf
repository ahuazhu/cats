variable "kubeconfig_path" {
  description = "Path to a kubeconfig generated for the existing production EKS cluster."
  type        = string
}

variable "kubeconfig_context" {
  description = "Exact production EKS kubeconfig context."
  type        = string
}

variable "expected_account_id" {
  description = "Exact AWS account allowed to contain the production application resources."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be an explicit 12-digit AWS account ID."
  }
}

variable "expected_aws_partition" {
  description = "Exact AWS partition allowed to contain the production application resources."
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

variable "control_plane_image" {
  description = "Immutable ECR cats-controld image with sha256 digest."
  type        = string
}

variable "gateway_image" {
  description = "Immutable ECR cats-gatewayd image with sha256 digest."
  type        = string
}

variable "object_write_gateway_image" {
  description = "Immutable ECR image containing cats-object-write-gatewayd, pinned by sha256 digest."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.object_write_gateway_image))
    error_message = "object_write_gateway_image must be pinned by sha256 digest."
  }
}

variable "object_write_gateway_replicas" {
  description = "Active-active ObjectWrite Gateway replicas."
  type        = number
  default     = 2

  validation {
    condition     = var.object_write_gateway_replicas >= 2 && floor(var.object_write_gateway_replicas) == var.object_write_gateway_replicas
    error_message = "object_write_gateway_replicas must be an integer of at least 2."
  }
}

variable "object_write_gateway_tls_secret_name" {
  description = "Pre-created immutable two-file Secret for the node-server-CA-issued serverAuth leaf."
  type        = string

  validation {
    condition = (
      can(regex("^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$", var.object_write_gateway_tls_secret_name)) &&
      endswith(var.object_write_gateway_tls_secret_name, "-r1")
    )
    error_message = "object_write_gateway_tls_secret_name must end in -r1."
  }
}

variable "object_write_gateway_nlb_security_group_id" {
  description = "Platform output for the internal NLB frontend SG."
  type        = string
}

variable "object_write_gateway_private_zone_id" {
  description = "Platform private Route53 zone ID for the stable gateway name."
  type        = string
}

variable "object_write_gateway_private_dns_name" {
  description = "Exact serverAuth SAN and Node CATS_OBJECT_WRITE_GATEWAY_URL hostname."
  type        = string

  validation {
    condition     = can(regex("^gateway\\.object-write\\.[a-z0-9-]+\\.cats\\.internal$", var.object_write_gateway_private_dns_name))
    error_message = "object_write_gateway_private_dns_name must be the platform-owned gateway.object-write.<environment>.cats.internal name."
  }
}

variable "object_write_spool_file_system_id" {
  description = "Platform encrypted EFS spool file system ID."
  type        = string
}

variable "object_write_spool_access_point_id" {
  description = "Platform EFS spool access point ID."
  type        = string
}

variable "control_plane_replicas" {
  description = "Active-active cats-controld API replica count."
  type        = number
  default     = 2

  validation {
    condition     = var.control_plane_replicas >= 2 && floor(var.control_plane_replicas) == var.control_plane_replicas
    error_message = "control_plane_replicas must be an integer of at least 2."
  }
}

variable "gateway_replicas" {
  description = "Active-active cats-gatewayd replica count."
  type        = number
  default     = 2

  validation {
    condition     = var.gateway_replicas >= 2 && floor(var.gateway_replicas) == var.gateway_replicas
    error_message = "gateway_replicas must be an integer of at least 2."
  }
}

variable "route_v2_control_artifact_secret_name" {
  description = "Pre-created immutable Kubernetes Secret name for the closed eight-file Control Route v2 artifact set."
  type        = string

  validation {
    condition = (
      can(regex("^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$", var.route_v2_control_artifact_secret_name)) &&
      endswith(var.route_v2_control_artifact_secret_name, "-r${var.route_v2_control_artifact_signer_revision}")
    )
    error_message = "route_v2_control_artifact_secret_name must end in the exact positive signer revision suffix."
  }
}

variable "route_v2_control_artifact_signer_revision" {
  description = "Positive signer revision encoded by the staged Control descriptor and immutable Secret name."
  type        = number

  validation {
    condition     = var.route_v2_control_artifact_signer_revision > 0 && floor(var.route_v2_control_artifact_signer_revision) == var.route_v2_control_artifact_signer_revision
    error_message = "route_v2_control_artifact_signer_revision must be a positive integer."
  }
}

variable "route_v2_control_artifact_secret_sha256" {
  description = "Canonical digest of the reviewed immutable Control Secret manifest; no secret bytes."
  type        = string

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.route_v2_control_artifact_secret_sha256))
    error_message = "route_v2_control_artifact_secret_sha256 must be canonical sha256:<64-lowerhex>."
  }
}

variable "route_v2_gateway_artifact_secret_name" {
  description = "Pre-created immutable Kubernetes Secret name for exactly the three fixed Gateway Route v2 artifacts."
  type        = string
}

variable "maintenance_mode" {
  description = "Reviewed clean-slate maintenance boundary: remove public ingress and DNS, and scale cats-controld to zero."
  type        = bool
  default     = false
}

variable "enable_public_ingress" {
  description = "Explicit reviewed public-ingress gate; remains false through fresh qualification and old retirement."
  type        = bool
  default     = false
}

variable "runtime_secret_data" {
  description = "WorkOS and Cats runtime secrets. Supply with TF_VAR_runtime_secret_data or an approved CI secret store."
  type        = map(string)
  sensitive   = true
}

variable "production_cutover_operator_trust_bundle_json" {
  description = "Release-bound public E13 operator trust bundle. cats-controld loads it at startup and refuses to start without it; it carries no private material."
  type        = string

  validation {
    condition     = can(jsondecode(var.production_cutover_operator_trust_bundle_json))
    error_message = "production_cutover_operator_trust_bundle_json must be JSON."
  }
}

variable "runtime_provisioner_trust_bundle_json" {
  description = "Canonical A23 deployment-provisioner public trust bundle. Supply from the central provisioning release."
  type        = string
}

variable "storage_postgres_url" {
  description = "ChunkStore metadata PostgreSQL URL."
  type        = string
  sensitive   = true
}

variable "control_postgres_schema" {
  description = "Exact fresh cats_* schema selected as search_path by controld, noded and every blockd."
  type        = string

  validation {
    condition     = can(regex("^cats_[a-z0-9_]+$", var.control_postgres_schema)) && length(var.control_postgres_schema) <= 63
    error_message = "control_postgres_schema must be one lowercase cats_* PostgreSQL identifier no longer than 63 bytes."
  }
}

variable "storage_postgres_session_setup" {
  description = "Where ChunkStore PostgreSQL session timeouts are established. Use server-verified only with an RDS Proxy initialization query."
  type        = string
  default     = "client"

  validation {
    condition     = contains(["client", "server-verified"], var.storage_postgres_session_setup)
    error_message = "storage_postgres_session_setup must be client or server-verified."
  }
}

variable "chunkstore_bucket_name" {
  description = "Platform stack chunkstore_bucket_name output."
  type        = string
}

variable "chunkstore_prefix" {
  description = "Exact object-key prefix shared by blockd and cats-controld."
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

variable "usage_postgres_url" {
  description = "Usage-ledger PostgreSQL URL; may initially point to the same RDS instance as storage_postgres_url."
  type        = string
  sensitive   = true
}

variable "usage_postgres_schema" {
  description = "Independent PostgreSQL schema for usage metering."
  type        = string

  validation {
    condition     = can(regex("^cats_[a-z0-9_]+$", var.usage_postgres_schema)) && length(var.usage_postgres_schema) <= 63
    error_message = "usage_postgres_schema must be one lowercase cats_* PostgreSQL identifier no longer than 63 bytes."
  }
}

variable "usage_postgres_workers" {
  description = "Usage PostgreSQL worker count."
  type        = number
  default     = 4
}

variable "usage_delivery_adapter" {
  description = "Durable usage delivery adapter."
  type        = string
  default     = "aws-kinesis"
}

variable "usage_aws_region" {
  description = "AWS region for the usage pipeline."
  type        = string
  default     = "us-east-1"
}

variable "usage_kinesis_stream" {
  description = "Kinesis usage stream name."
  type        = string
  default     = ""
}

variable "usage_archive_bucket" {
  description = "Immutable S3 usage archive bucket name."
  type        = string
  default     = ""
}

variable "usage_checkpoint_table" {
  description = "DynamoDB usage projector checkpoint table name."
  type        = string
  default     = ""
}

variable "stripe_enabled" {
  description = "Enable Terraform-managed Stripe hosted top-ups in cats-controld."
  type        = bool
  default     = false
}

variable "stripe_secret_key" {
  description = "Stripe secret key. Supply through TF_VAR_stripe_secret_key or an approved CI secret store."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true
}

variable "stripe_webhook_secret" {
  description = "Sensitive webhook_secret output from the production-payments state."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true
}

variable "stripe_topup_price_ids" {
  description = "topup_price_ids output from the production-payments state."
  type        = map(string)
  default     = {}
}

variable "stripe_livemode" {
  description = "Expected Stripe object mode."
  type        = bool
  default     = true
}

variable "rds_ca_pem" {
  description = "RDS CA PEM bundle. Prefer supplying it from CI rather than checking a copied bundle into this repository."
  type        = string
}

variable "acm_certificate_arn" {
  description = "ACM certificate for cats.run and its wildcard."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs used by the EKS Auto Mode ALB."
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs used by the ObjectWrite Gateway internal NLB."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "private_subnet_ids must span at least two subnets."
  }
}

variable "control_plane_hosts" {
  description = "Hosts routed to cats-controld."
  type        = list(string)
  default     = ["cats.run", "app.cats.run", "admin.cats.run", "ops.cats.run"]
}

variable "endpoint_wildcard_host" {
  description = "Wildcard Endpoint host routed only to cats-gatewayd."
  type        = string
  default     = "*.cats.run"
}

variable "aws_region" {
  description = "Region holding the load balancer and the hosted zone."
  type        = string
  default     = "us-east-1"
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be an explicit AWS region name."
  }
}

variable "route53_zone_id" {
  description = "Hosted zone receiving alias records for every public host. Null leaves DNS to another system."
  type        = string
  default     = null
}

variable "credential_refresher_image" {
  description = "Digest-pinned credential-refresher image. Supplied by the deployment; null disables the refresher."
  type        = string
  default     = null
}

variable "credential_refresher_mode" {
  description = "`report` verifies and writes nothing; `patch` also writes. Start in report (ADR-0029 staging)."
  type        = string
  default     = "report"
}

variable "database_master_user_secret_arn" {
  description = "RDS managed master user secret the refresher reconciles the runtime Secret against."
  type        = string
  default     = null
}

variable "route_rotation_nlb_security_group_id" {
  description = "Security group for the internal NLB that makes the Route v2 rotation Service reachable from the VPC's bare-metal Node Agents. Null keeps it ClusterIP-only."
  type        = string
  default     = null
}

variable "route_rotation_private_zone_id" {
  description = "Private hosted zone that resolves the rotation Service's cluster-local name for VPC clients. Null leaves the name cluster-internal."
  type        = string
  default     = null
}
