variable "namespace" {
  description = "Kubernetes namespace that owns all Cats application resources."
  type        = string
  default     = "cats"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a valid Kubernetes DNS label."
  }
}

variable "control_plane_image" {
  description = "Immutable cats-controld container image, including its sha256 digest."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.control_plane_image))
    error_message = "control_plane_image must be pinned by sha256 digest."
  }
}

variable "control_plane_replicas" {
  description = "Number of active-active control-plane API replicas; singleton loops elect independently through PostgreSQL."
  type        = number
  default     = 2

  validation {
    condition     = var.control_plane_replicas >= 2 && floor(var.control_plane_replicas) == var.control_plane_replicas
    error_message = "control_plane_replicas must be an integer of at least 2."
  }
}

variable "gateway_image" {
  description = "Immutable cats-gatewayd container image, including its sha256 digest."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.gateway_image))
    error_message = "gateway_image must be pinned by sha256 digest."
  }
}

variable "runtime_secret_data" {
  description = "Additional cats-runtime environment variables, such as WorkOS credentials and Cats service tokens."
  type        = map(string)
  sensitive   = true

  validation {
    condition = length(setintersection(
      toset(keys(var.runtime_secret_data)),
      toset([
        "CATS_POSTGRES_URL",
        "CATS_USAGE_STORE_ADAPTER",
        "CATS_USAGE_POSTGRES_URL",
        "CATS_USAGE_POSTGRES_SCHEMA",
        "CATS_USAGE_POSTGRES_WORKERS",
        "CATS_USAGE_POSTGRES_CA_FILE",
        "CATS_USAGE_DELIVERY_ADAPTER",
        "CATS_USAGE_AWS_REGION",
        "CATS_USAGE_KINESIS_STREAM",
        "CATS_USAGE_ARCHIVE_BUCKET",
        "CATS_USAGE_CHECKPOINT_TABLE",
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "CATS_STRIPE_TOPUP_PRICES",
        "CATS_STRIPE_CHECKOUT_SUCCESS_URL",
        "CATS_STRIPE_CHECKOUT_CANCEL_URL",
        "CATS_STRIPE_LIVEMODE",
        "CATS_BILLING_ENFORCEMENT_ENABLED",
      ])
    )) == 0
    error_message = "runtime_secret_data cannot override Terraform-managed storage or usage database settings."
  }

  validation {
    condition = alltrue([
      for key in ["CATS_AUTH_TOKEN", "CATS_ADMIN_TOKEN"] :
      try(length(trimspace(var.runtime_secret_data[key])) >= 32, false)
    ])
    error_message = "runtime_secret_data must contain CATS_AUTH_TOKEN and CATS_ADMIN_TOKEN, each at least 32 characters."
  }
}

variable "route_grant_private_key_pem" {
  description = "PKCS#8 Ed25519 private key mounted only into cats-controld for Endpoint Route Grant signing."
  type        = string
  sensitive   = true

  validation {
    condition = (
      startswith(trimspace(var.route_grant_private_key_pem), "-----BEGIN PRIVATE KEY-----") &&
      endswith(trimspace(var.route_grant_private_key_pem), "-----END PRIVATE KEY-----")
    )
    error_message = "route_grant_private_key_pem must be a PKCS#8 PEM private key."
  }
}

variable "route_grant_public_key_pem" {
  description = "Ed25519 public key derived from route_grant_private_key_pem and mounted into cats-controld for startup pair verification."
  type        = string

  validation {
    condition = (
      startswith(trimspace(var.route_grant_public_key_pem), "-----BEGIN PUBLIC KEY-----") &&
      endswith(trimspace(var.route_grant_public_key_pem), "-----END PUBLIC KEY-----")
    )
    error_message = "route_grant_public_key_pem must be a PEM public key."
  }
}

variable "storage_postgres_url" {
  description = "PostgreSQL URL used for ChunkStore roots, leases, and fencing."
  type        = string
  sensitive   = true

  validation {
    condition = (
      startswith(var.storage_postgres_url, "postgresql://") ||
      startswith(var.storage_postgres_url, "postgres://")
      ) && (
      strcontains(var.storage_postgres_url, "sslmode=require") ||
      strcontains(var.storage_postgres_url, "sslmode=verify-ca") ||
      strcontains(var.storage_postgres_url, "sslmode=verify-full")
    )
    error_message = "storage_postgres_url must be a PostgreSQL URL with an explicit TLS sslmode."
  }
}

variable "storage_postgres_session_setup" {
  description = "Where ChunkStore PostgreSQL session timeouts are established. server-verified avoids client SET statements that pin RDS Proxy sessions."
  type        = string
  default     = "client"

  validation {
    condition     = contains(["client", "server-verified"], var.storage_postgres_session_setup)
    error_message = "storage_postgres_session_setup must be client or server-verified."
  }
}

variable "usage_postgres_url" {
  description = "PostgreSQL URL used for the usage ledger. It may initially point to the shared RDS instance."
  type        = string
  sensitive   = true

  validation {
    condition = (
      startswith(var.usage_postgres_url, "postgresql://") ||
      startswith(var.usage_postgres_url, "postgres://")
      ) && (
      strcontains(var.usage_postgres_url, "sslmode=require") ||
      strcontains(var.usage_postgres_url, "sslmode=verify-ca") ||
      strcontains(var.usage_postgres_url, "sslmode=verify-full")
    )
    error_message = "usage_postgres_url must be a PostgreSQL URL with an explicit TLS sslmode."
  }
}

variable "usage_postgres_schema" {
  description = "Schema owned by the usage adapter."
  type        = string
  default     = "cats_usage"

  validation {
    condition     = can(regex("^[A-Za-z_][A-Za-z0-9_]*$", var.usage_postgres_schema))
    error_message = "usage_postgres_schema must be a valid unquoted PostgreSQL identifier."
  }
}

variable "usage_postgres_workers" {
  description = "Number of blocking PostgreSQL workers used by cats-controld."
  type        = number
  default     = 4

  validation {
    condition     = var.usage_postgres_workers >= 1 && var.usage_postgres_workers <= 32 && floor(var.usage_postgres_workers) == var.usage_postgres_workers
    error_message = "usage_postgres_workers must be an integer between 1 and 32."
  }
}

variable "usage_delivery_adapter" {
  description = "Durable usage delivery adapter."
  type        = string
  default     = "direct"

  validation {
    condition     = contains(["direct", "aws-kinesis"], var.usage_delivery_adapter)
    error_message = "usage_delivery_adapter must be direct or aws-kinesis."
  }
}

variable "usage_aws_region" {
  description = "AWS region for the usage stream and archive."
  type        = string
  default     = "us-east-1"
}

variable "usage_kinesis_stream" {
  description = "Kinesis stream used when usage_delivery_adapter is aws-kinesis."
  type        = string
  default     = ""
}

variable "usage_archive_bucket" {
  description = "Immutable S3 usage archive bucket."
  type        = string
  default     = ""
}

variable "usage_checkpoint_table" {
  description = "DynamoDB projector checkpoint table."
  type        = string
  default     = ""
}

variable "stripe_enabled" {
  description = "Enable Stripe-hosted prepaid top-ups."
  type        = bool
  default     = false
}

variable "stripe_secret_key" {
  description = "Stripe secret API key used only by cats-controld."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true
}

variable "stripe_webhook_secret" {
  description = "Signing secret exported by the Terraform-managed Stripe webhook endpoint."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true
}

variable "stripe_topup_price_ids" {
  description = "Map of fixed USD-cent amounts to Terraform-managed Stripe Price IDs."
  type        = map(string)
  default     = {}
}

variable "stripe_checkout_success_url" {
  type    = string
  default = "https://cats.run/user/?topup=success&session_id={CHECKOUT_SESSION_ID}"

  validation {
    condition     = startswith(var.stripe_checkout_success_url, "https://")
    error_message = "stripe_checkout_success_url must use HTTPS."
  }
}

variable "stripe_checkout_cancel_url" {
  type    = string
  default = "https://cats.run/user/?topup=cancelled"

  validation {
    condition     = startswith(var.stripe_checkout_cancel_url, "https://")
    error_message = "stripe_checkout_cancel_url must use HTTPS."
  }
}

variable "stripe_livemode" {
  description = "Reject webhook events whose livemode flag differs from this value."
  type        = bool
  default     = true
}

variable "rds_ca_pem" {
  description = "PEM bundle used to verify the RDS PostgreSQL TLS certificate."
  type        = string

  validation {
    condition     = strcontains(var.rds_ca_pem, "BEGIN CERTIFICATE")
    error_message = "rds_ca_pem must contain at least one PEM certificate."
  }
}

variable "auto_warm_after_seconds" {
  description = "Seconds before an eligible Suspended Cat becomes Warm; zero disables the transition."
  type        = number
  default     = 600

  validation {
    condition     = var.auto_warm_after_seconds >= 0 && floor(var.auto_warm_after_seconds) == var.auto_warm_after_seconds
    error_message = "auto_warm_after_seconds must be a non-negative integer."
  }
}

variable "auto_cold_after_seconds" {
  description = "Seconds before an eligible Warm Cat becomes Cold; zero disables the transition."
  type        = number
  default     = 86400

  validation {
    condition     = var.auto_cold_after_seconds >= 0 && floor(var.auto_cold_after_seconds) == var.auto_cold_after_seconds
    error_message = "auto_cold_after_seconds must be a non-negative integer."
  }
}

variable "gateway_replicas" {
  description = "Number of stateless endpoint gateway replicas."
  type        = number
  default     = 2

  validation {
    condition     = var.gateway_replicas >= 2 && floor(var.gateway_replicas) == var.gateway_replicas
    error_message = "gateway_replicas must be an integer of at least 2."
  }
}

variable "shared_route_cache_table" {
  description = "DynamoDB table that replicates short-lived signed Route Grants across Gateway replicas. Null disables it outside production."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.shared_route_cache_table == null ||
      can(regex("^[A-Za-z0-9_.-]{3,255}$", var.shared_route_cache_table))
    )
    error_message = "shared_route_cache_table must be null or a valid DynamoDB table name."
  }
}

variable "enable_public_ingress" {
  description = "Create the EKS Auto Mode ALB ingress resources."
  type        = bool
  default     = true
}

variable "ingress_class_name" {
  description = "Name of the EKS Auto Mode IngressClass and IngressClassParams."
  type        = string
  default     = "cats-public"
}

variable "oci_deploy_sync_wait_ms" {
  description = <<-EOT
    How long POST /oci-deployments holds a request open before answering 202
    with an operation to poll. A transition affordance for callers written
    against the older synchronous response; lower it as callers adopt polling.
  EOT
  type        = number
  default     = 240000
}

variable "public_ingress_idle_timeout_seconds" {
  description = <<-EOT
    ALB idle timeout for the public ingress.

    AWS defaults this to 60 s, which is shorter than several legitimate Cats
    requests: an OCI deploy pulls and flattens an image, and `exec` accepts a
    caller-supplied timeout up to an hour. When the target has not answered by
    the idle timeout the ALB returns 504, which says nothing about whether the
    work succeeded -- it did keep running -- so callers retried operations that
    were already in flight.

    This must stay above the control plane's `--oci-deploy-sync-wait-ms`, or
    the ALB answers 504 before the control plane can answer 202.
  EOT
  type        = number
  default     = 300

  validation {
    condition     = var.public_ingress_idle_timeout_seconds >= 60 && var.public_ingress_idle_timeout_seconds <= 4000
    error_message = "ALB idle timeout must be between 60 and 4000 seconds."
  }
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN used by the public HTTPS listener."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = !var.enable_public_ingress || (var.acm_certificate_arn != null && startswith(var.acm_certificate_arn, "arn:"))
    error_message = "acm_certificate_arn is required when public ingress is enabled."
  }
}

variable "public_subnet_ids" {
  description = "Every public subnet in which EKS Auto Mode may place the ALB."
  type        = list(string)
  default     = []

  validation {
    condition     = !var.enable_public_ingress || length(var.public_subnet_ids) >= 2
    error_message = "At least two public subnet IDs are required when public ingress is enabled."
  }
}

variable "control_plane_hosts" {
  description = "Public hostnames routed to cats-controld."
  type        = list(string)
  default     = ["cats.run", "app.cats.run", "admin.cats.run", "ops.cats.run"]

  validation {
    condition     = length(var.control_plane_hosts) == length(toset(var.control_plane_hosts))
    error_message = "control_plane_hosts must not contain duplicates."
  }
}

variable "endpoint_wildcard_host" {
  description = "Wildcard hostname routed to cats-gatewayd."
  type        = string
  default     = "*.cats.run"

  validation {
    condition     = startswith(var.endpoint_wildcard_host, "*.")
    error_message = "endpoint_wildcard_host must begin with '*.'."
  }
}

variable "credential_refresher_image" {
  description = <<-EOT
    Digest-pinned image running the in-cluster credential refresher, built from
    Dockerfile.control-plane's `credential-refresher` target. Null disables the
    refresher entirely, which leaves the window described in ADR-0029 open: a
    rotation followed by an unplanned Pod restart before the next deploy.
  EOT
  type        = string
  default     = null
}

variable "credential_refresher_mode" {
  description = <<-EOT
    `report` reads the authority, composes the DSNs and proves they authenticate,
    then logs what it would change and writes nothing. `patch` additionally
    writes. Run in `report` until it has judged correctly against the real
    instance for several cycles (ADR-0029 staging): the failure this guards
    against is writing a wrong password that only surfaces at the next restart.
  EOT
  type        = string
  default     = "report"

  validation {
    condition     = contains(["report", "patch"], var.credential_refresher_mode)
    error_message = "credential_refresher_mode must be report or patch."
  }
}

variable "credential_refresher_schedule" {
  description = "Cron schedule bounding how long a rotated password can sit unreconciled."
  type        = string
  default     = "*/15 * * * *"
}

variable "credential_refresher_service_account" {
  description = "ServiceAccount name. Must match the infrastructure stack's Pod Identity association."
  type        = string
  default     = "cats-credential-refresher"
}

variable "database_master_user_secret_arn" {
  description = "RDS managed master user secret the refresher reconciles against. Required when credential_refresher_image is set."
  type        = string
  default     = null

  validation {
    condition = (
      var.database_master_user_secret_arn == null ||
      can(regex("^arn:[^:]+:secretsmanager:", var.database_master_user_secret_arn))
    )
    error_message = "database_master_user_secret_arn must be a Secrets Manager ARN."
  }
}
