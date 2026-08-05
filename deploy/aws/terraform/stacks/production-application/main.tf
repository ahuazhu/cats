module "cats_kubernetes" {
  source = "../../modules/cats-kubernetes"

  control_plane_image    = var.control_plane_image
  gateway_image          = var.gateway_image
  runtime_secret_data    = var.runtime_secret_data
  storage_postgres_url   = var.storage_postgres_url
  usage_postgres_url     = var.usage_postgres_url
  usage_postgres_schema  = var.usage_postgres_schema
  usage_postgres_workers = var.usage_postgres_workers
  usage_delivery_adapter = var.usage_delivery_adapter
  usage_aws_region       = var.usage_aws_region
  usage_kinesis_stream   = var.usage_kinesis_stream
  usage_archive_bucket   = var.usage_archive_bucket
  usage_checkpoint_table = var.usage_checkpoint_table
  stripe_enabled         = var.stripe_enabled
  stripe_secret_key      = var.stripe_secret_key
  stripe_webhook_secret  = var.stripe_webhook_secret
  stripe_topup_price_ids = var.stripe_topup_price_ids
  stripe_livemode        = var.stripe_livemode
  rds_ca_pem             = var.rds_ca_pem

  # In-cluster reconciliation of the database credential (ADR-0029, #77). The
  # Pod Identity association it needs lives in the infrastructure state.
  credential_refresher_image      = var.credential_refresher_image
  credential_refresher_mode       = var.credential_refresher_mode
  database_master_user_secret_arn = var.database_master_user_secret_arn
  auto_warm_after_seconds         = var.auto_warm_after_seconds
  auto_cold_after_seconds         = var.auto_cold_after_seconds
  acm_certificate_arn             = var.acm_certificate_arn
  public_subnet_ids               = var.public_subnet_ids
  control_plane_hosts             = var.control_plane_hosts
  endpoint_wildcard_host          = var.endpoint_wildcard_host
}

# Public DNS.
#
# The hosted zone belongs to the platform state, but the load balancer only
# exists once this stack's ingress reconciles, so the alias records that join
# them belong here. The account this replaces had these records created by hand,
# which is why a rebuild had no way to know they were needed.
#
# Set route53_zone_id to enable; leave it null when a different system owns DNS.
locals {
  manage_dns = var.route53_zone_id != null

  dns_hosts = toset(concat(
    var.control_plane_hosts,
    var.endpoint_wildcard_host == null ? [] : [var.endpoint_wildcard_host],
  ))
}

# Located by the tag EKS puts on the load balancer it provisions, because the
# generated name is not stable across a recreate.
data "aws_lb" "public" {
  count = local.manage_dns ? 1 : 0

  tags = {
    "ingress.eks.amazonaws.com/stack" = "${module.cats_kubernetes.namespace}/${module.cats_kubernetes.ingress_name}"
  }

  depends_on = [module.cats_kubernetes]
}

resource "aws_route53_record" "public" {
  for_each = local.manage_dns ? local.dns_hosts : toset([])

  zone_id = var.route53_zone_id
  name    = each.value
  type    = "A"

  alias {
    name                   = data.aws_lb.public[0].dns_name
    zone_id                = data.aws_lb.public[0].zone_id
    evaluate_target_health = true
  }
}
