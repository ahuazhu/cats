variable "kubeconfig_path" {
  description = "Path to a kubeconfig generated for the existing production EKS cluster."
  type        = string
}

variable "kubeconfig_context" {
  description = "Exact production EKS kubeconfig context."
  type        = string
}

variable "control_plane_image" {
  description = "Immutable ECR cats-controld image with sha256 digest."
  type        = string
}

variable "gateway_image" {
  description = "Immutable ECR cats-gatewayd image with sha256 digest."
  type        = string
}

variable "runtime_secret_data" {
  description = "WorkOS and Cats runtime secrets. Supply with TF_VAR_runtime_secret_data or an approved CI secret store."
  type        = map(string)
  sensitive   = true
}

variable "storage_postgres_url" {
  description = "ChunkStore metadata PostgreSQL URL."
  type        = string
  sensitive   = true
}

variable "usage_postgres_url" {
  description = "Usage-ledger PostgreSQL URL; may initially point to the same RDS instance as storage_postgres_url."
  type        = string
  sensitive   = true
}

variable "usage_postgres_schema" {
  description = "Independent PostgreSQL schema for usage metering."
  type        = string
  default     = "cats_usage"
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

variable "control_plane_hosts" {
  description = "Hosts routed to cats-controld."
  type        = list(string)
  default     = ["cats.run", "app.cats.run", "admin.cats.run", "ops.cats.run"]
}

variable "endpoint_wildcard_host" {
  description = "Wildcard endpoint host routed to cats-gatewayd."
  type        = string
  default     = "*.cats.run"
}

variable "auto_warm_after_seconds" {
  type    = number
  default = 600
}

variable "auto_cold_after_seconds" {
  type    = number
  default = 86400
}

variable "aws_region" {
  description = "Region holding the load balancer and the hosted zone."
  type        = string
  default     = "us-east-1"
}

variable "route53_zone_id" {
  description = "Hosted zone receiving alias records for every public host. Null leaves DNS to another system."
  type        = string
  default     = null
}
