module "cats_kubernetes" {
  source = "../../modules/cats-kubernetes"

  control_plane_image     = var.control_plane_image
  gateway_image           = var.gateway_image
  runtime_secret_data     = var.runtime_secret_data
  storage_postgres_url    = var.storage_postgres_url
  usage_postgres_url      = var.usage_postgres_url
  usage_postgres_schema   = var.usage_postgres_schema
  usage_postgres_workers  = var.usage_postgres_workers
  usage_delivery_adapter  = var.usage_delivery_adapter
  usage_aws_region        = var.usage_aws_region
  usage_kinesis_stream    = var.usage_kinesis_stream
  usage_archive_bucket    = var.usage_archive_bucket
  usage_checkpoint_table  = var.usage_checkpoint_table
  stripe_enabled          = var.stripe_enabled
  stripe_secret_key       = var.stripe_secret_key
  stripe_webhook_secret   = var.stripe_webhook_secret
  stripe_topup_price_ids  = var.stripe_topup_price_ids
  stripe_livemode         = var.stripe_livemode
  rds_ca_pem              = var.rds_ca_pem
  auto_warm_after_seconds = var.auto_warm_after_seconds
  auto_cold_after_seconds = var.auto_cold_after_seconds
  acm_certificate_arn     = var.acm_certificate_arn
  public_subnet_ids       = var.public_subnet_ids
  control_plane_hosts     = var.control_plane_hosts
  endpoint_wildcard_host  = var.endpoint_wildcard_host
}
